from .base import FeatureBlock
import pefile
import numpy as np

class GeneralFileInfo(FeatureBlock):
    """
    Extracts general information about the file.
    EMBER-compatible (10 features).
    """

    @property
    def name(self) -> str:
        return "GeneralFileInfo"

    @property
    def dim(self) -> int:
        return 10

    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        features = np.zeros(self.dim, dtype=np.float32)
        
        # 1. Virtual Size (of the PE)
        # Sum of VirtualSize of all sections? Or SizeOfImage?
        # EMBER uses pe.OPTIONAL_HEADER.SizeOfImage usually, 
        # but let's check if it's the sum of sections virtual size. 
        # Actually SizeOfImage is in Header features.
        # General -> usually purely statistical or summarized.
        # Let's use file size and virtual size.
        
        if raw_data:
            features[0] = len(raw_data)
        else:
            # Fallback if raw_data not provided, though it should be.
            features[0] = 0 

        # 2. Virtual Size
        features[1] = pe.OPTIONAL_HEADER.SizeOfImage

        # 3. Has Debug
        features[2] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0

        # 4. Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features[3] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        else:
            features[3] = 0

        # 5. Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features[4] = sum([len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT])
        else:
            features[4] = 0

        # 6. Has Relocations
        features[5] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') else 0

        # 7. Has Resources
        features[6] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0

        # 8. Has Signature
        features[7] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else 0

        # 9. Has TLS
        features[8] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0

        # 10. Symbols
        features[9] = pe.FILE_HEADER.NumberOfSymbols

        return features
