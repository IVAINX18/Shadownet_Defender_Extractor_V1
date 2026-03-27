from .base import FeatureBlock
from ._math_utils import hash_feature_sha256
import pefile
import numpy as np

class ImportsFeatureBlock(FeatureBlock):
    """
    Extracts features from the Import Address Table (IAT) using feature hashing.
    
    Each import (DLL:function) is mapped to a deterministic index in a vector
    of 1280 dimensions using SHA256 hash.
    
    Compatible with SOREL-20M (1280 features).
    """
    
    # Output vector dimension
    DIM = 1280
    
    @property
    def name(self) -> str:
        return "ImportsFeatureBlock"
    
    @property
    def dim(self) -> int:
        return self.DIM
    
    @staticmethod
    def _normalize_name(name: str) -> str:
        """
        Normalizes DLL/function names for cross-sample consistency.
        
        Operations:
        - Strip whitespace
        - Lowercase (KERNEL32.DLL -> kernel32.dll)
        - Remove .dll extension if exists
        
        Args:
            name: Original name (can be None)
            
        Returns:
            Normalized name (empty string if None)
        """
        if name is None:
            return ""
        
        # Convert to lowercase and remove spaces
        normalized = name.strip().lower()
        
        # Remove .dll extension if exists (for uniformity)
        if normalized.endswith('.dll'):
            normalized = normalized[:-4]
        
        return normalized
    
    # 📚 NOTA: _hash_feature se movió a _math_utils.hash_feature_sha256()
    # para evitar duplicación con exports.py y section_info.py.
    
    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        """
        Extracts features from the Import Table using feature hashing.
        
        Args:
            pe: Parsed pefile.PE object
            raw_data: Raw bytes (not used, required by interface)
            
        Returns:
            Array of 1280 float32, normalized (sum ~ 1.0 if imports exist)
        """
        # Initialize counter vector
        vector = np.zeros(self.DIM, dtype=np.float32)
        
        # Check if PE has Import Table
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return vector
        
        # Iterate over each imported DLL
        for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                # Decode DLL name
                dll_name_bytes = dll_entry.dll
                if isinstance(dll_name_bytes, bytes):
                    dll_name = dll_name_bytes.decode('utf-8', errors='replace')
                else:
                    dll_name = str(dll_name_bytes)
                
                # Normalize DLL name
                dll_name = self._normalize_name(dll_name)
            except Exception:
                dll_name = "unknown"
            
            # Iterate over imported functions
            for func in dll_entry.imports:
                try:
                    # Check if import by name or ordinal
                    if func.name:
                        # Import by name
                        func_name_bytes = func.name
                        if isinstance(func_name_bytes, bytes):
                            func_name = func_name_bytes.decode('utf-8', errors='replace')
                        else:
                            func_name = str(func_name_bytes)
                        
                        func_name = self._normalize_name(func_name)
                    else:
                        # Import by ordinal
                        func_name = f"ord{func.ordinal}"
                except Exception:
                    func_name = "unknown"
                
                # Create feature string: "dll:function"
                feature = f"{dll_name}:{func_name}"
                
                # Calculate hash and get index
                index = hash_feature_sha256(feature, self.DIM)
                
                # Increment counter
                vector[index] += 1
        
        # Normalization: relative frequency
        total = vector.sum()
        if total > 0:
            vector = vector / total
            
        return vector
