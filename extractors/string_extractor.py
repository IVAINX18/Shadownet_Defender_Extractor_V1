from .base import FeatureBlock
import pefile
import numpy as np
import re
import math

class StringExtractorBlock(FeatureBlock):
    """
    Extracts string-based features and IoCs.
    
    Features (104):
    - Global stats (5)
    - IoC Patterns (10)
    - Length Hist (40)
    - Entropy Hist (40)
    - Char stats (9)
    """
    
    DIM = 104
    
    # Regex Patterns (Bytes for performance)
    REGEX_ASCII = re.compile(rb'[\x20-\x7E]{4,}')
    
    REGEX_URL = re.compile(rb'https?://[\w\-\.]+')
    REGEX_PATH = re.compile(rb'[C-Z]:\\[\w\\]+|/usr/bin/|/bin/|/tmp/')
    REGEX_IP = re.compile(rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    REGEX_REGISTRY = re.compile(rb'HKEY_[\w]+|HKLM|HKCU')
    REGEX_EMAIL = re.compile(rb'[\w\.-]+@[\w\.-]+\.\w+')
    REGEX_MZ = re.compile(rb'MZ') # Embedded PE
    REGEX_POWERSHELL = re.compile(rb'powershell|cmd\.exe|bitsadmin', re.IGNORECASE)
    REGEX_CRYPTO = re.compile(rb'bitcoin|wallet|monero|crypto', re.IGNORECASE)
    REGEX_API = re.compile(rb'LoadLibrary|GetProcAddress|VirtualAlloc|CreateRemoteThread', re.IGNORECASE)
    REGEX_FMT = re.compile(rb'%[sdxf]')
    
    LEN_BINS = 40
    ENT_BINS = 40
    
    @property
    def name(self) -> str:
        return "StringExtractorBlock"
    
    @property
    def dim(self) -> int:
        return self.DIM

    def _calculate_entropy(self, data: bytes) -> float:
        if not data: return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts[counts > 0] / len(data)
        return -np.sum(probs * np.log2(probs))

    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        vector = np.zeros(self.DIM, dtype=np.float32)
        
        # 1. Harvesting
        all_strings = self.REGEX_ASCII.findall(raw_data)
        
        num_strings = len(all_strings)
        if num_strings == 0:
            return vector
            
        # 2. Analysis
        lengths = []
        entropies = []
        total_chars = 0
        
        count_url = 0
        count_path = 0
        count_ip = 0
        count_reg = 0
        count_email = 0
        count_mz = 0
        count_ps = 0
        count_crypto = 0
        count_api = 0
        count_fmt = 0
        
        c_digits = 0
        c_upper = 0
        c_lower = 0
        c_space = 0
        c_special = 0
        
        for s in all_strings:
            slen = len(s)
            lengths.append(slen)
            total_chars += slen
            
            ent = self._calculate_entropy(s)
            entropies.append(ent)
            
            # IoC Check
            if slen > 4:
                if self.REGEX_URL.search(s): count_url += 1
                if self.REGEX_PATH.search(s): count_path += 1
                if self.REGEX_IP.search(s): count_ip += 1
                if self.REGEX_REGISTRY.search(s): count_reg += 1
                if self.REGEX_EMAIL.search(s): count_email += 1
                if self.REGEX_POWERSHELL.search(s): count_ps += 1
                if self.REGEX_CRYPTO.search(s): count_crypto += 1
                if self.REGEX_API.search(s): count_api += 1
            
            if s.startswith(b'MZ'): count_mz += 1
            if self.REGEX_FMT.search(s): count_fmt += 1
            
            # Char Analysis
            arr = np.frombuffer(s, dtype=np.uint8)
            c_digits += np.sum((arr >= 48) & (arr <= 57))
            c_upper += np.sum((arr >= 65) & (arr <= 90))
            c_lower += np.sum((arr >= 97) & (arr <= 122))
            c_space += np.sum(arr == 32)
            
        c_special = total_chars - (c_digits + c_upper + c_lower + c_space)
        
        # 3. Vectorization
        
        # A: Global Stats (0-4)
        vector[0] = np.log1p(num_strings)
        vector[1] = np.mean(lengths)
        vector[2] = np.max(lengths)
        vector[3] = np.mean(entropies)
        vector[4] = np.log1p(total_chars)
        
        # B: IoCs (5-14)
        vector[5] = count_path
        vector[6] = count_url
        vector[7] = count_reg
        vector[8] = count_mz
        vector[9] = count_ip
        vector[10] = count_email
        vector[11] = count_api
        vector[12] = count_ps
        vector[13] = count_crypto
        vector[14] = count_fmt
        
        # C: Histograms (15-94)
        for l in lengths:
            val = math.log2(l)
            bin_idx = int((val / 20.0) * (self.LEN_BINS - 1))
            bin_idx = max(0, min(bin_idx, self.LEN_BINS - 1))
            vector[15 + bin_idx] += 1
            
        if num_strings > 0:
            vector[15:55] /= num_strings
            
        for e in entropies:
            bin_idx = int((e / 8.0) * (self.ENT_BINS - 1))
            bin_idx = max(0, min(bin_idx, self.ENT_BINS - 1))
            vector[55 + bin_idx] += 1
            
        if num_strings > 0:
            vector[55:95] /= num_strings
            
        # D: Char Stats (95-103)
        if total_chars > 0:
            vector[95] = c_digits / total_chars
            vector[96] = c_upper / total_chars
            vector[97] = c_lower / total_chars
            vector[98] = c_space / total_chars
            vector[99] = c_special / total_chars
            vector[100] = (c_digits + c_special) / total_chars
            vector[101] = c_lower / (c_upper + c_lower + 1e-6)
            vector[102] = 0
            vector[103] = 0
            
        return vector
