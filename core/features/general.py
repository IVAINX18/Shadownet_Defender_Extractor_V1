from .base import FeatureBlock
import pefile
import numpy as np

class GeneralFileInfo(FeatureBlock):
    """
    Extrae información general sobre el archivo.
    Compatible con EMBER (10 características).
    """

    @property
    def name(self) -> str:
        return "GeneralFileInfo"

    @property
    def dim(self) -> int:
        return 10

    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        features = np.zeros(self.dim, dtype=np.float32)
        
        # 1. Tamaño del archivo (basado en raw_data si está disponible)
        if raw_data:
            features[0] = len(raw_data)
        else:
            # Valor por defecto si no se proporcionan datos crudos
            features[0] = 0 

        # 2. Tamaño Virtual (SizeOfImage)
        features[1] = pe.OPTIONAL_HEADER.SizeOfImage

        # 3. Tiene Debug (Información de depuración)
        features[2] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0

        # 4. Exportaciones (Número de símbolos exportados)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features[3] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        else:
            features[3] = 0

        # 5. Importaciones (Total de funciones importadas)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features[4] = sum([len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT])
        else:
            features[4] = 0

        # 6. Tiene Relocalizaciones
        features[5] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') else 0

        # 7. Tiene Recursos
        features[6] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0

        # 8. Tiene Firma Digital (Directorio de Seguridad)
        features[7] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else 0

        # 9. Tiene TLS (Thread Local Storage)
        features[8] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0

        # 10. Número de Símbolos en el Header
        features[9] = pe.FILE_HEADER.NumberOfSymbols

        return features
