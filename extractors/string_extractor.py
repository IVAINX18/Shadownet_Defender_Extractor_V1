from .base import FeatureBlock
from ._math_utils import calculate_shannon_entropy, get_distributed_sample
import pefile
import numpy as np
import re
import math
import logging

logger = logging.getLogger(__name__)

class StringExtractorBlock(FeatureBlock):
    """
    Extracts string-based features and IoCs.
    
    Features (104):
    - Global stats (5)
    - IoC Patterns (10)
    - Length Hist (40)
    - Entropy Hist (40)
    - Char stats (9)

    * NOTA DE SEGURIDAD — Límites anti-DoS:

        MAX_SCAN_BYTES: El regex se aplica solo sobre los primeros N bytes del
        archivo. El malware inflado (bloated) añade gigabytes de zeros al final.
        Sin este límite, REGEX_ASCII.findall() sobre 500 MB puede consumir toda
        la RAM disponible y bloquear el proceso.

        MAX_STRINGS: Solo se analizan en detalle los primeros M strings. Si un
        archivo tiene 500,000 strings, el bucle de entropía de Shannon (que crea
        arreglos NumPy en cada iteración) tardaría varios minutos. El muestreo
        uniforme preserva la distribución estadística sin el costo computacional.
    """
    
    DIM = 104

    # Anti-bloating: limitar el área de búsqueda de strings.
    # Los primeros 10 MB contienen el código y datos significativos del PE.
    MAX_SCAN_BYTES = 10 * 1024 * 1024  # 10 MB

    # Anti-DoS: máximo de strings a analizar en profundidad.
    # Si hay más, se toma una muestra uniforme para preservar la distribución.
    MAX_STRINGS = 5_000

    # Regex Patterns (Bytes for performance)
    REGEX_ASCII = re.compile(rb'[\x20-\x7E]{4,}')
    
    # Patrón híbrido de evasión para priorizar strings críticos (APIs, shells, herramientas de control)
    REGEX_SUSPICIOUS = re.compile(
        rb"(?:cmd\.exe|powershell|rundll32|schtasks|regsvr32|virtualalloc|"
        rb"createremotethread|writeprocessmemory|mimikatz|lsass|wscript|"
        rb"cscript|bitsadmin|certutil|http://|https://|hkey_|\.exe|\.dll|\.ps1|\.bat)",
        re.IGNORECASE
    )
    
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

    # * NOTA: _calculate_entropy se movió a _math_utils.py para evitar duplicación.

    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        vector = np.zeros(self.DIM, dtype=np.float32)

        # Anti-bloating: muestreo distribuido si excede MAX_SCAN_BYTES.
        original_size = len(raw_data)
        scan_data = raw_data
        if original_size > self.MAX_SCAN_BYTES:
            logger.warning(
                "StringExtractor: archivo grande (%d bytes). Aplicando muestreo "
                "distribuido de %d bytes para evitar OOM y evasión.",
                original_size,
                self.MAX_SCAN_BYTES,
            )
            scan_data = get_distributed_sample(raw_data, self.MAX_SCAN_BYTES)

        # 1. Harvesting
        all_strings = self.REGEX_ASCII.findall(scan_data)
        
        num_strings = len(all_strings)
        if num_strings == 0:
            return vector

        # Anti-DoS / Anti-evasión (Billion Strings Attack):
        # Si el número de strings excede MAX_STRINGS, usamos una estrategia híbrida:
        # 1. Extraer y priorizar strings que coinciden con REGEX_SUSPICIOUS o son largos (> 64 bytes).
        # 2. Rellenar el resto de la cuota con muestreo uniforme del resto de strings.
        if num_strings > self.MAX_STRINGS:
            logger.warning(
                "StringExtractor: %d strings encontrados, aplicando muestreo híbrido "
                "inteligente (limite %d) para priorizar IoCs y evadir Billion Strings.",
                num_strings,
                self.MAX_STRINGS,
            )
            high_priority = []
            regular = []
            
            for s in all_strings:
                # Priorizar si es largo (> 64 bytes) o coincide con el regex de sospechosos
                if len(s) > 64 or self.REGEX_SUSPICIOUS.search(s):
                    high_priority.append(s)
                else:
                    regular.append(s)
            
            # De-duplicar prioritarios para maximizar diversidad y firmas únicas
            unique_high = list(set(high_priority))
            
            if len(unique_high) >= self.MAX_STRINGS:
                # Si los prioritarios exceden el límite, tomamos una muestra uniforme de ellos
                step = len(unique_high) / self.MAX_STRINGS
                indices = [int(i * step) for i in range(self.MAX_STRINGS)]
                sampled_strings = [unique_high[i] for i in indices]
            else:
                # Si no cubren toda la cuota, rellenamos con strings comunes muestreados uniformemente
                sampled_strings = unique_high
                needed = self.MAX_STRINGS - len(unique_high)
                if regular:
                    step = len(regular) / needed
                    indices = [int(i * step) for i in range(needed)]
                    sampled_strings.extend([regular[i] for i in indices])
        else:
            sampled_strings = all_strings
            
        # 2. Analysis (sobre la muestra)
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
        
        for s in sampled_strings:
            slen = len(s)
            lengths.append(slen)
            total_chars += slen
            
            ent = calculate_shannon_entropy(s)
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
        # Usamos num_strings original (no el de la muestra) para reflejar la
        # escala real del archivo, que es un feature discriminante de malware.
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
        num_sampled = len(sampled_strings)
        for l in lengths:
            val = math.log2(l)
            bin_idx = int((val / 20.0) * (self.LEN_BINS - 1))
            bin_idx = max(0, min(bin_idx, self.LEN_BINS - 1))
            vector[15 + bin_idx] += 1
            
        if num_sampled > 0:
            vector[15:55] /= num_sampled
            
        for e in entropies:
            bin_idx = int((e / 8.0) * (self.ENT_BINS - 1))
            bin_idx = max(0, min(bin_idx, self.ENT_BINS - 1))
            vector[55 + bin_idx] += 1
            
        if num_sampled > 0:
            vector[55:95] /= num_sampled
            
        # D: Char Stats (95-103)
        if total_chars > 0:
            vector[95] = c_digits / total_chars
            vector[96] = c_upper / total_chars
            vector[97] = c_lower / total_chars
            vector[98] = c_space / total_chars
            vector[99] = c_special / total_chars
            vector[100] = (c_digits + c_special) / total_chars
            vector[101] = c_lower / (c_upper + c_lower + 1e-6)
            # * Índices 102-103: Reservados para features futuras
            # (ej: ratio de strings ofuscadas, diversidad léxica)
            vector[102] = 0
            vector[103] = 0
            
        return vector
