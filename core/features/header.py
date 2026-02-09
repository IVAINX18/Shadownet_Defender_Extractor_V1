from .base import FeatureBlock
import pefile
import numpy as np

class HeaderFileInfo(FeatureBlock):
    """
    Extrae información del encabezado PE (Portable Executable).
    Compatible con EMBER (62 características).
    """

    @property
    def name(self) -> str:
        return "HeaderFileInfo"

    @property
    def dim(self) -> int:
        return 62

    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        features = np.zeros(self.dim, dtype=np.float32)
        idx = 0

        # Cabecera COFF (File Header)
        features[idx] = pe.FILE_HEADER.TimeDateStamp; idx += 1  # Marca de tiempo
        features[idx] = pe.FILE_HEADER.Machine; idx += 1        # Arquitectura (x86, x64, etc.)
        features[idx] = pe.FILE_HEADER.Characteristics; idx += 1 # Características (DLL, Executable, etc.)
        
        # Cabecera Opcional (Optional Header)
        features[idx] = pe.OPTIONAL_HEADER.Subsystem; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.DllCharacteristics; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.Magic; idx += 1       # PE32 vs PE32+
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
        
        # Usamos los valores tal cual vienen en pefile
        features[idx] = pe.OPTIONAL_HEADER.SizeOfHeapReserve; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfStackCommit; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfStackReserve; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SizeOfImage; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.SectionAlignment; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.FileAlignment; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.CheckSum; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.AddressOfEntryPoint; idx += 1
        features[idx] = pe.OPTIONAL_HEADER.BaseOfCode; idx += 1
        
        # BaseOfData solo existe en PE32 (32-bits), no en PE32+ (64-bits)
        if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData'):
            features[idx] = pe.OPTIONAL_HEADER.BaseOfData
        else:
            features[idx] = 0
        idx += 1
        
        features[idx] = pe.OPTIONAL_HEADER.ImageBase; idx += 1
        
        # Directorios de Datos (Data Directories) - Usualmente hay 16
        # Extraemos tamaño y dirección virtual para cada uno
        # 16 directorios * 2 valores = 32 características
        
        for i in range(len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
             # Asegurar no desbordar el límite de 62 características
            if idx >= self.dim - 1: 
                break
                
            entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
            features[idx] = entry.Size; idx += 1
            features[idx] = entry.VirtualAddress; idx += 1
            
        # Rellenar si hay menos directorios de lo esperado
        # Standard: 27 características escalares + 32 de directorios = 59.
        # Faltan 3 para llegar a 62.
        # EMBER incluye LoaderFlags y NumberOfRvaAndSizes.
        
        if idx < self.dim:
            features[idx] = pe.OPTIONAL_HEADER.LoaderFlags; idx += 1
        
        if idx < self.dim:
             features[idx] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes; idx += 1
             
        # Rellenar con ceros si aún sobra espacio
        while idx < self.dim:
            features[idx] = 0
            idx += 1
            
        return features
