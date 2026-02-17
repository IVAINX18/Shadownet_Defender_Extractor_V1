import pefile
import numpy as np
from core.features.extractor import PEFeatureExtractor

# Global instance to avoid re-initialization overhead if reused
_sorel_extractor = PEFeatureExtractor()

def extract_basic_pe_features(file_path: str) -> np.ndarray:
    """
    Legacy basic extractor. Keeps original behavior.
    """
    pe = pefile.PE(file_path)

    features = [
        pe.FILE_HEADER.Machine,
        pe.FILE_HEADER.NumberOfSections,
        pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        pe.OPTIONAL_HEADER.ImageBase,
        pe.OPTIONAL_HEADER.SizeOfImage,
        pe.OPTIONAL_HEADER.Subsystem
    ]

    return np.array(features, dtype=np.float32)

def extract_sorel_features(file_path: str) -> np.ndarray:
    """
    Extracts 2381 features compatible with SOREL/EMBER models.
    Uses the new modular feature extractor.
    """
    return _sorel_extractor.extract(file_path)
