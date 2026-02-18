from .base import FeatureBlock
from ._math_utils import hash_feature_sha256
import pefile
import numpy as np

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

    # 📚 NOTA: _hash_feature se movió a _math_utils.hash_feature_sha256()
    # para evitar duplicación con imports.py y section_info.py.

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
                    except Exception:
                        func_name = f"ord{exp.ordinal}"
                else:
                    func_name = f"ord{exp.ordinal}"
                
                # Hashing
                idx = hash_feature_sha256(func_name, self.DIM)
                
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
