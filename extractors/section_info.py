from .base import FeatureBlock
from ._math_utils import calculate_shannon_entropy, hash_feature_sha256
import pefile
import numpy as np
import math

class SectionInfoBlock(FeatureBlock):
    """
    Extracts detailed features from PE sections.
    
    Includes global statistics, flags, entropy distribution, raw/virtual size distributions,
    and hashed section names.
    
    Dimensions (Total: 255):
    - Global Stats (10)
    - Flags & Permissions (5)
    - Entropy Dist (50)
    - Raw Size Dist (50)
    - Virt Size Dist (50)
    - Hashed Names (90)
    """
    
    # Fixed Total Dimension
    DIM = 255
    
    # Histogram Configurations
    ENTROPY_BINS = 50
    SIZE_BINS = 50
    NAME_HASH_BINS = 90
    
    @property
    def name(self) -> str:
        return "SectionInfoBlock"
    
    @property
    def dim(self) -> int:
        return self.DIM
        
    # 📚 NOTA: _calculate_entropy y _hash_name se movieron a _math_utils.py
    # para evitar duplicación DRY. Se usan las funciones compartidas importadas arriba.

    def _hash_name(self, name: str) -> int:
        """Deterministic hash for section names using shared utility."""
        if not name:
            return 0
        normalized = name.strip().lower().replace('\x00', '')
        return hash_feature_sha256(normalized, self.NAME_HASH_BINS)

    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        vector = np.zeros(self.DIM, dtype=np.float32)
        
        sections = pe.sections
        num_sections = len(sections)
        
        raw_sizes = []
        virt_sizes = []
        entropies = []
        
        count_exec = 0
        count_write = 0
        count_read = 0
        count_rwx = 0
        count_shared = 0
        
        hist_entropy = np.zeros(self.ENTROPY_BINS, dtype=np.float32)
        hist_raw_size = np.zeros(self.SIZE_BINS, dtype=np.float32)
        hist_virt_size = np.zeros(self.SIZE_BINS, dtype=np.float32)
        hist_names = np.zeros(self.NAME_HASH_BINS, dtype=np.float32)
        
        if num_sections > 0:
            for section in sections:
                r_size = section.SizeOfRawData
                v_size = section.Misc_VirtualSize
                
                raw_sizes.append(r_size)
                virt_sizes.append(v_size)
                
                try:
                    sect_data = section.get_data()
                    entropy = calculate_shannon_entropy(sect_data)
                except Exception:
                    entropy = 0.0
                entropies.append(entropy)
                
                # Flags
                props = getattr(section, 'Characteristics', 0)
                is_exec = (props & 0x20000000) > 0
                is_read = (props & 0x40000000) > 0
                is_write = (props & 0x80000000) > 0
                is_shared = (props & 0x10000000) > 0
                
                if is_exec: count_exec += 1
                if is_read: count_read += 1
                if is_write: count_write += 1
                if is_shared: count_shared += 1
                if is_read and is_write and is_exec: count_rwx += 1
                
                # Name Hashing
                try:
                    name = section.Name.decode('utf-8', errors='replace')
                except Exception:
                    name = ""
                name_idx = self._hash_name(name)
                hist_names[name_idx] += 1
                
                # Histograms
                e_bin = int((entropy / 8.0) * (self.ENTROPY_BINS - 1))
                e_bin = max(0, min(e_bin, self.ENTROPY_BINS - 1))
                hist_entropy[e_bin] += 1
                
                if r_size > 0:
                    log_r = math.log2(r_size + 1)
                    r_bin = int((log_r / 26.0) * (self.SIZE_BINS - 1))
                    r_bin = max(0, min(r_bin, self.SIZE_BINS - 1))
                    hist_raw_size[r_bin] += 1
                else:
                    hist_raw_size[0] += 1
                    
                if v_size > 0:
                    log_v = math.log2(v_size + 1)
                    v_bin = int((log_v / 26.0) * (self.SIZE_BINS - 1))
                    v_bin = max(0, min(v_bin, self.SIZE_BINS - 1))
                    hist_virt_size[v_bin] += 1
                else:
                    hist_virt_size[0] += 1

        # Vectorization
        
        # A: Global Stats (0-9)
        vector[0] = num_sections
        vector[1] = sum(1 for s in raw_sizes if s == 0)
        vector[2] = np.mean(raw_sizes) if raw_sizes else 0
        vector[3] = np.mean(virt_sizes) if virt_sizes else 0
        vector[4] = np.average(entropies, weights=raw_sizes) if raw_sizes and sum(raw_sizes) > 0 else 0
        vector[5] = min(entropies) if entropies else 0
        vector[6] = max(entropies) if entropies else 0
        
        ratios = []
        for r, v in zip(raw_sizes, virt_sizes):
            if v > 0: ratios.append(r / v)
            else: ratios.append(0)
        vector[7] = np.mean(ratios) if ratios else 0
        
        vector[8] = sum(raw_sizes)
        vector[9] = sum(virt_sizes)
        
        # B: Flags (10-14)
        vector[10] = count_exec
        vector[11] = count_write
        vector[12] = count_read
        vector[13] = count_rwx
        vector[14] = count_shared
        
        # C: Distributions (Normalized)
        if num_sections > 0:
            hist_entropy /= num_sections
            hist_raw_size /= num_sections
            hist_virt_size /= num_sections
            hist_names /= num_sections
            
        vector[15 : 15 + self.ENTROPY_BINS] = hist_entropy
        vector[65 : 65 + self.SIZE_BINS] = hist_raw_size
        vector[115 : 115 + self.SIZE_BINS] = hist_virt_size
        vector[165 : 165 + self.NAME_HASH_BINS] = hist_names
        
        return vector
