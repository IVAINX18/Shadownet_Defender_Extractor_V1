import pefile
import numpy as np
from .base import FeatureBlock
from .general import GeneralFileInfo
from .header import HeaderFileInfo
from .byte_histogram import ByteHistogram
from .byte_entropy import ByteEntropy

class PEFeatureExtractor:
    """
    Extractor de características principal que combina múltiples bloques de características
    para producir un vector compatible con SOREL/EMBER.
    """
    
    def __init__(self, feature_version: int = 2):
        self.blocks = [
            # Orden estándar de EMBER 2.0 / SOREL:
            # 1. ByteHistogram (256) - Pendiente de implementar
            # 2. ByteEntropy (256) - Pendiente de implementar
            # 3. StringExtractor (104) - Pendiente de implementar
            # 4. GeneralFileInfo (10)
            # 5. HeaderFileInfo (62)
            # 6. SectionInfo (255) - Pendiente de implementar
            # 7. Imports (1280) - Pendiente de implementar
            # 8. Exports (128) - Pendiente de implementar
            
            # Actualmente solo tenemos General y Header.
            # Debemos respetar el ORDEN en el vector final.
        ]
        
        # Instanciamos los bloques implementados
        self.byte_histogram_block = ByteHistogram()
        self.byte_entropy_block = ByteEntropy()
        self.general_block = GeneralFileInfo()
        self.header_block = HeaderFileInfo()
        
        # Dimensión total esperada (definida por el usuario/modelo)
        self.total_dim = 2381
        
    def extract(self, file_path: str) -> np.ndarray:
        """
        Extrae características de un archivo PE.
        Devuelve un array de float32 con forma (2381,).
        """
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
        except Exception as e:
            # Si no se puede leer el archivo, ¿devolver ceros o lanzar error?
            # Por ahora lanzamos el error.
            raise e
            
        try:
            pe = pefile.PE(data=raw_data)
        except pefile.PEFormatError:
            # Si no es un PE válido, devolver vector de ceros
             return np.zeros(self.total_dim, dtype=np.float32)

        # Inicializar el vector final con ceros
        final_vector = np.zeros(self.total_dim, dtype=np.float32)
        
        # Mapeo de características basado en la estructura de EMBER 2.0:
        # 0-255: ByteHistogram
        # 256-511: ByteEntropy
        # 512-615: Strings (104)
        # 616-625: GeneralFileInfo (10)  <-- Aquí insertamos
        # 626-687: HeaderFileInfo (62)   <-- Y aquí
        # 688-942: SectionInfo (255)
        # 943-2222: Imports (1280)
        # 2223-2350: Exports (128)
        # Total base: 2351.
        
        # El usuario indicó 2381. La diferencia de 30 suele ser DataDirectories tratados aparte,
        # pero mi implementación de Header ya incluye DataDirectories, así que mantendremos
        # el offset relativo estándar.
        
        # Offset para ByteHistogram: 0-255
        byte_hist_feats = self.byte_histogram_block.extract(pe, raw_data)
        final_vector[0:256] = byte_hist_feats
        
        # Offset para ByteEntropy: 256-511
        byte_entropy_feats = self.byte_entropy_block.extract(pe, raw_data)
        final_vector[256:512] = byte_entropy_feats
        
        # Offset para GeneralFileInfo: 616
        offset_general = 616
        
        # Extraer características Generales
        general_feats = self.general_block.extract(pe, raw_data)
        final_vector[offset_general : offset_general + self.general_block.dim] = general_feats
        
        # Offset para HeaderFileInfo: 626
        offset_header = 626
        
        # Extraer características de Cabecera (Header)
        header_feats = self.header_block.extract(pe, raw_data)
        final_vector[offset_header : offset_header + self.header_block.dim] = header_feats
        
        return final_vector
