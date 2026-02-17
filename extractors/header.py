from .base import FeatureBlock
import pefile
import numpy as np

class HeaderFileInfo(FeatureBlock):
    """
    Extracts PE header information.
    Compatible with EMBER (62 features).
    """

    @property
    def name(self) -> str:
        return "HeaderFileInfo"

    @property
    def dim(self) -> int:
        return 62

    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        features = np.zeros(self.dim, dtype=np.float32)
        idx = 0

        # COFF Header
        features[idx] = pe.FILE_HEADER.TimeDateStamp; idx += 1
        features[idx] = pe.FILE_HEADER.Machine; idx += 1
        features[idx] = pe.FILE_HEADER.Characteristics; idx += 1
        
        # Optional Header
        features[idx] = pe.OPTIONAL_HEADER.Subsystem; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.DllCharacteristics; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.Magic; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.MajorImageVersion; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.MinorImageVersion; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.MajorLinkerVersion; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.MinorLinkerVersion; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.MajorSubsystemVersion; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.MinorSubsystemVersion; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfCode; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfHeaders; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfHeapCommit; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfHeapReserve; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfStackCommit; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfStackReserve; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfImage; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SectionAlignment; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.FileAlignment; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.CheckSum; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.AddressOfEntryPoint; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.BaseOfCode; idx += 1
        
        # BaseOfData exists only in PE32 (not PE32+)
        if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData'):
            features[idx] = pe.OPTIONAL_HEADER.BaseOfData
        else:
            features[idx] = 0
        idx += 1
        
        features[idx] = pe.OPTIONAL_HEADER.ImageBase; idx += 1
        
        # Data Directories (usually 16)
        # Extract Size and VirtualAddress for each
        for i in range(len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
            if idx >= self.dim - 1: 
                break
            entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
            features[idx] = entry.Size; idx += 1
            features[idx] = entry.VirtualAddress; idx += 1
            
        # Optional Header additional fields
        if idx < self.dim:
            features[idx] = pe.OPTIONAL_HEADER.LoaderFlags; idx += 1
        
        if idx < self.dim:
             features[idx] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes; idx += 1
             
        # Padding
        while idx < self.dim:
            features[idx] = 0
            idx += 1
            
        return features
