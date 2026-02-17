from abc import ABC, abstractmethod
import numpy as np
import pefile

class FeatureBlock(ABC):
    """
    Abstract base class for all feature extraction blocks.
    
    All feature extractors must inherit from this class and implement
    the `extract` method and `dim` property.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the feature block."""
        pass

    @property
    @abstractmethod
    def dim(self) -> int:
        """Returns the dimension of the feature vector produced by this block."""
        pass

    @abstractmethod
    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        """
        Extracts features from the PE file.

        Args:
            pe: parsed pefile.PE object.
            raw_data: raw bytes of the file.

        Returns:
            np.ndarray: Feature vector of shape (dim,).
        """
        pass
