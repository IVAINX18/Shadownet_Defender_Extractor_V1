from .base import FeatureBlock
import pefile
import numpy as np

class GeneralFileInfo(FeatureBlock):
    """
    Extracts general file information.
    Compatible with EMBER (10 features).
    """

    @property
    def name(self) -> str:
        return "GeneralFileInfo"

    @property
    def dim(self) -> int:
        return 10

    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        features = np.zeros(self.dim, dtype=np.float32)
        
        if raw_data:
            features[0] = len(raw_data)
        else:
            features[0] = 0 

        features[1] = pe.OPTIONAL_HEADER.SizeOfImage
        features[2] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features[3] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        else:
            features[3] = 0

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features[4] = sum([len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT])
        else:
            features[4] = 0

        features[5] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') else 0
        features[6] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
        features[7] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else 0
        features[8] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0
        features[9] = pe.FILE_HEADER.NumberOfSymbols

        return features
