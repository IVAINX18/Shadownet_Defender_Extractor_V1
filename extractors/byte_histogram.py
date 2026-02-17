from .base import FeatureBlock
import pefile
import numpy as np

class ByteHistogram(FeatureBlock):
    """
    Extracts the byte histogram of the file.
    Represents the normalized frequency distribution of all bytes [0x00-0xFF].
    
    Compatible with EMBER/SOREL (256 features).
    """
    
    @property
    def name(self) -> str:
        return "ByteHistogram"
    
    @property
    def dim(self) -> int:
        return 256
    
    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        """
        Calculates the normalized byte histogram.
        
        Args:
            pe: pefile.PE object (not used directly, but required by interface)
            raw_data: Raw bytes of the file
            
        Returns:
            Array of 256 float32 values, where each position i contains the relative
            frequency of byte i in the file. Sum of all values is 1.0.
        """
        # Initialize with zeros
        histogram = np.zeros(self.dim, dtype=np.float32)
        
        # Validate we have data
        if raw_data is None or len(raw_data) == 0:
            return histogram
        
        # Calculate histogram using bincount (efficient)
        # bincount counts how many times each value appears in the array
        counts = np.bincount(np.frombuffer(raw_data, dtype=np.uint8), minlength=256)
        
        # Normalize by total bytes
        total_bytes = len(raw_data)
        if total_bytes > 0:
            histogram = counts.astype(np.float32) / total_bytes
        
        # Validation: sum must be 1.0 (probability distribution)
        # We use a small epsilon for floating point comparisons
        # assert np.isclose(histogram.sum(), 1.0, atol=1e-6)
        
        return histogram
