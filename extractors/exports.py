from .base import FeatureBlock
import pefile
import numpy as np
import hashlib

class ExportsFeatureBlock(FeatureBlock):
    """
    Extracts features from the Export Directory using Feature Hashing.
    Maps exported function names to a fixed-size vector.
    
    Compatible with EMBER (128 features).
    """
    
    # Fixed dimension of 128 features
    DIM = 128
    
    @property
    def name(self) -> str:
        return "ExportsFeatureBlock"
    
    @property
    def dim(self) -> int:
        return self.DIM

    def _hash_feature(self, feature: str) -> int:
        """
        Applies deterministic hashing using SHA256.
        Returns an index in range [0, 127].
        """
        digest = hashlib.sha256(feature.encode('utf-8', errors='replace')).digest()
        val = int.from_bytes(digest[:8], 'little')
        return val % self.DIM

    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        """
        Extracts the 128-dim exports vector.
        """
        vector = np.zeros(self.DIM, dtype=np.float32)
        
        # Check if Export Directory exists
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return vector

        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                # Check for name or ordinal
                if exp.name:
                    try:
                        func_name = exp.name.decode('utf-8', errors='ignore').strip().lower()
                    except:
                        func_name = f"ord{exp.ordinal}"
                else:
                    func_name = f"ord{exp.ordinal}"
                
                # Hashing
                idx = self._hash_feature(func_name)
                
                # Vectorization
                vector[idx] += 1
                
        except AttributeError:
             # Robust handling of malformed PEs
            pass
            
        # L1 Normalization (Relative Frequency)
        total = np.sum(vector)
        if total > 0:
            vector = vector / total
            
        return vector
