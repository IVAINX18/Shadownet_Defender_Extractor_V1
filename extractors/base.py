from abc import ABC, abstractmethod
import numpy as np
import pefile


class FeatureBlock(ABC):
    """
    Clase base abstracta para todos los bloques de extracción de features.

    PARA JUNIORS — ¿Qué es una Clase Abstracta (ABC)?

        Una ABC define un "contrato" que todas las subclases DEBEN cumplir.
        En ShadowNet, cada bloque de features (ByteHistogram, ByteEntropy,
        ImportsFeatureBlock, etc.) hereda de esta clase y DEBE implementar:

        1. `name` → Nombre identificador del bloque (para logging/debug)
        2. `dim`  → Cuántas dimensiones produce (ej: ByteHistogram → 256)
        3. `extract()` → La lógica real de extracción de features

        Si un desarrollador crea un nuevo bloque y olvida implementar alguno
        de estos métodos, Python lanzará un TypeError al instanciar la clase.
        Esto previene bugs silenciosos.

    ¿Por qué usamos este patrón?

        Gracias a esta abstracción, PEFeatureExtractor (en extractor.py) puede
        iterar sobre una lista de FeatureBlock sin saber qué tipo concreto es
        cada uno. Esto se llama "Principio de Sustitución de Liskov" (SOLID/L).
        Podemos agregar un nuevo bloque de features simplemente creando una nueva
        clase que herede de FeatureBlock, sin modificar el extractor principal.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Retorna el nombre del bloque de features (usado en logs y debug)."""
        pass

    @property
    @abstractmethod
    def dim(self) -> int:
        """Retorna la dimensión del vector que produce este bloque."""
        pass

    @abstractmethod
    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        """
        Extrae features del archivo PE.

        Args:
            pe: Objeto pefile.PE ya parseado.
            raw_data: Bytes crudos del archivo completo.

        Returns:
            np.ndarray: Vector de features con shape (dim,).
        """
        pass

