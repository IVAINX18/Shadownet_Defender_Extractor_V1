from abc import ABC, abstractmethod
import pefile
import numpy as np

class FeatureBlock(ABC):
    """
    Clase base abstracta para un bloque de características.
    Cada bloque es responsable de extraer un subconjunto específico de características
    del archivo PE.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Devuelve el nombre de este bloque de características."""
        pass

    @property
    @abstractmethod
    def dim(self) -> int:
        """Devuelve la dimensión (número de características) de este bloque."""
        pass

    @abstractmethod
    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        """
        Extrae características del archivo PE dado o de los datos sin procesar.
        
        Args:
            pe: Objeto pefile.PE analizado.
            raw_data: Bytes sin procesar del archivo (opcional, usado para características a nivel de byte).
            
        Returns:
            Un array de numpy con forma (dim,) y dtype=float32.
        """
        pass
