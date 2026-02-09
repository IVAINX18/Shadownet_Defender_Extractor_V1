from abc import ABC, abstractmethod
import pefile
import numpy as np

class FeatureBlock(ABC):
    """
    Abstract base class for a feature block.
    Each block is responsible for extracting a specific subset of features
    from the PE file.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of this feature block."""
        pass

    @property
    @abstractmethod
    def dim(self) -> int:
        """Returns the dimension (number of features) of this block."""
        pass

    @abstractmethod
    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        """
        Extracts features from the given PE file or raw data.
        
        Args:
            pe: Parsed pefile.PE object.
            raw_data: Raw bytes of the file (optional, used for byte-level features).
            
        Returns:
            A numpy array of shape (dim,) with dtype=float32.
        """
        pass
