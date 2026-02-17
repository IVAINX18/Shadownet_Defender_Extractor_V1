from .base import FeatureBlock
import pefile
import numpy as np

class ByteHistogram(FeatureBlock):
    """
    Extrae el histograma de bytes del archivo.
    Representa la distribución de frecuencia normalizada de todos los bytes [0x00-0xFF].
    
    Compatible con EMBER/SOREL (256 características).
    """
    
    @property
    def name(self) -> str:
        return "ByteHistogram"
    
    @property
    def dim(self) -> int:
        return 256
    
    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        """
        Calcula el histograma normalizado de bytes.
        
        Args:
            pe: Objeto pefile.PE (no utilizado directamente, pero requerido por la interfaz)
            raw_data: Bytes sin procesar del archivo
            
        Returns:
            Array de 256 valores float32, donde cada posición i contiene la frecuencia
            relativa del byte i en el archivo. La suma de todos los valores es 1.0.
        """
        # Inicializar con ceros
        histogram = np.zeros(self.dim, dtype=np.float32)
        
        # Validar que tenemos datos
        if raw_data is None or len(raw_data) == 0:
            return histogram
        
        # Calcular histograma usando bincount (eficiente)
        # bincount cuenta cuántas veces aparece cada valor en el array
        counts = np.bincount(np.frombuffer(raw_data, dtype=np.uint8), minlength=256)
        
        # Normalizar por el total de bytes
        total_bytes = len(raw_data)
        histogram = counts.astype(np.float32) / total_bytes
        
        # Validación: la suma debe ser 1.0 (distribución de probabilidad)
        assert np.isclose(histogram.sum(), 1.0, atol=1e-6), \
            f"ByteHistogram suma incorrecta: {histogram.sum()}"
        
        # Validación: todos los valores deben estar en [0, 1]
        assert np.all(histogram >= 0) and np.all(histogram <= 1), \
            "ByteHistogram contiene valores fuera de rango [0, 1]"
        
        return histogram
