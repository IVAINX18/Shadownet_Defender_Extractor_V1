"""
MockModel compartido para scripts de evaluación y testing.

📚 PARA JUNIORS:
    Cuando el modelo real (LightGBM o ONNX) no está disponible,
    este MockModel proporciona predicciones heurísticas basadas en
    la entropía del bloque ByteEntropy (posiciones 256-511 del vector).

    IMPORTANTE: Esto NO es un modelo de producción. Solo sirve para
    que los scripts de evaluación y robustez puedan ejecutarse sin
    necesidad del modelo entrenado real.
"""

import numpy as np


class MockModel:
    """
    Modelo heurístico de respaldo para evaluación.

    Simula predicciones basadas en la entropía promedio del bloque
    ByteEntropy (posiciones 256-511 del vector de 2381 dimensiones).
    Malware suele tener entropía más alta → valores cercanos a 1.
    """

    # Rango de índices del bloque ByteEntropy en el vector de features
    _ENTROPY_START = 256
    _ENTROPY_END = 512

    # Umbral heurístico para clasificar como malware
    _THRESHOLD = 0.5

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predice etiquetas binarias (0=benigno, 1=malware)."""
        entropy_mean = np.mean(
            X[:, self._ENTROPY_START : self._ENTROPY_END], axis=1
        )
        return (entropy_mean > self._THRESHOLD).astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predice probabilidades aproximadas [prob_benigno, prob_malware].

        La probabilidad se mapea linealmente desde la entropía promedio.
        """
        entropy_mean = np.mean(
            X[:, self._ENTROPY_START : self._ENTROPY_END], axis=1
        )
        # Mapear rango [0.2, 0.7] → [0.0, 1.0] aprox
        probs = np.clip((entropy_mean - 0.2) * 2, 0, 1)
        return np.vstack([1 - probs, probs]).T
