from .base import FeatureBlock
import pefile
import numpy as np

class ByteEntropy(FeatureBlock):
    """
    Extrae el histograma de entropía local del archivo mediante ventanas deslizantes.
    
    Calcula la entropía de Shannon en ventanas de tamaño fijo y construye un histograma
    de los valores de entropía encontrados. Esto permite detectar secciones empaquetadas,
    cifradas o con diferentes niveles de complejidad.
    
    Compatible con EMBER/SOREL (256 características).
    """
    
    # Parámetros estándar basados en EMBER 2.0
    WINDOW_SIZE = 2048  # Tamaño de ventana en bytes
    STEP_SIZE = 1024    # Stride (overlap de 50%)
    NUM_BINS = 256      # Número de bins para el histograma
    
    @property
    def name(self) -> str:
        return "ByteEntropy"
    
    @property
    def dim(self) -> int:
        return self.NUM_BINS
    
    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """
        Calcula la entropía de Shannon de un bloque de datos.
        
        H(X) = -Σ p(x) * log₂(p(x))
        
        Args:
            data: Bytes del bloque
            
        Returns:
            Entropía en bits (rango [0, 8] para bytes)
        """
        if len(data) == 0:
            return 0.0
        
        # Contar frecuencia de cada byte
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        
        # Calcular probabilidades (frecuencia relativa)
        probabilities = counts / len(data)
        
        # Filtrar probabilidades cero para evitar log(0)
        probabilities = probabilities[probabilities > 0]
        
        # Calcular entropía: -Σ p(x) * log₂(p(x))
        entropy = -np.sum(probabilities * np.log2(probabilities))
        
        return entropy
    
    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        """
        Calcula el histograma de entropía usando ventanas deslizantes.
        
        Args:
            pe: Objeto pefile.PE (no utilizado directamente)
            raw_data: Bytes sin procesar del archivo
            
        Returns:
            Array de 256 valores float32 representando la distribución de valores
            de entropía en el archivo. La suma de todos los valores es 1.0.
        """
        # Inicializar histograma
        entropy_histogram = np.zeros(self.NUM_BINS, dtype=np.float32)
        
        # Validar que tenemos datos
        if raw_data is None or len(raw_data) == 0:
            return entropy_histogram
        
        # Lista para almacenar valores de entropía de cada ventana
        entropy_values = []
        
        # Caso especial: archivo muy pequeño (menor que una ventana)
        if len(raw_data) < self.WINDOW_SIZE:
            # Calcular entropía del archivo completo como única ventana
            entropy = self._calculate_shannon_entropy(raw_data)
            entropy_values.append(entropy)
        else:
            # Ventanas deslizantes normales
            for i in range(0, len(raw_data) - self.WINDOW_SIZE + 1, self.STEP_SIZE):
                window = raw_data[i:i + self.WINDOW_SIZE]
                entropy = self._calculate_shannon_entropy(window)
                entropy_values.append(entropy)
        
        # Si no hay ventanas (no debería pasar), devolver ceros
        if len(entropy_values) == 0:
            return entropy_histogram
        
        # Convertir a array numpy
        entropy_values = np.array(entropy_values, dtype=np.float32)
        
        # Crear histograma de entropías
        # Rango de entropía: [0, 8] bits (máximo para 256 símbolos posibles)
        # Dividir en NUM_BINS bins
        hist, _ = np.histogram(entropy_values, bins=self.NUM_BINS, range=(0, 8))
        
        # Normalizar por el número total de ventanas
        entropy_histogram = hist.astype(np.float32) / len(entropy_values)
        
        # Validación: la suma debe ser aproximadamente 1.0
        assert np.isclose(entropy_histogram.sum(), 1.0, atol=1e-5), \
            f"ByteEntropy suma incorrecta: {entropy_histogram.sum()}"
        
        # Validación: todos los valores deben estar en [0, 1]
        assert np.all(entropy_histogram >= 0) and np.all(entropy_histogram <= 1), \
            "ByteEntropy contiene valores fuera de rango [0, 1]"
        
        return entropy_histogram
