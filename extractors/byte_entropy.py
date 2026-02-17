from .base import FeatureBlock
import pefile
import numpy as np

class ByteEntropy(FeatureBlock):
    """
    Extracts the local entropy histogram of the file using sliding windows.
    
    Calculates Shannon entropy on fixed-size windows and constructs a histogram
    of the entropy values found. This helps detect packed, encrypted, or 
    varying complexity sections.
    
    Compatible with EMBER/SOREL (256 features).
    """
    
    # Standard parameters based on EMBER 2.0
    WINDOW_SIZE = 2048  # Window size in bytes
    STEP_SIZE = 1024    # Stride (50% overlap)
    NUM_BINS = 256      # Number of bins for the histogram
    
    @property
    def name(self) -> str:
        return "ByteEntropy"
    
    @property
    def dim(self) -> int:
        return self.NUM_BINS
    
    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """
        Calculates Shannon entropy of a data block.
        
        H(X) = -Σ p(x) * log2(p(x))
        
        Args:
            data: Block bytes
            
        Returns:
            Entropy in bits (range [0, 8] for bytes)
        """
        if not data:
            return 0.0
        
        # Count frequency of each byte
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        
        # Calculate probabilities (relative frequency)
        probabilities = counts / len(data)
        
        # Filter zero probabilities to avoid log(0)
        probabilities = probabilities[probabilities > 0]
        
        # Calculate entropy: -Σ p(x) * log2(p(x))
        entropy = -np.sum(probabilities * np.log2(probabilities))
        
        return float(entropy)
    
    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        """
        Calculates entropy histogram using sliding windows.
        
        Args:
            pe: pefile.PE object (not used directly)
            raw_data: Raw bytes of the file
            
        Returns:
            Array of 256 float32 values representing the distribution of entropy
            values in the file. Sum of all values is 1.0.
        """
        # Initialize histogram
        entropy_histogram = np.zeros(self.NUM_BINS, dtype=np.float32)
        
        # Validate we have data
        if raw_data is None or len(raw_data) == 0:
            return entropy_histogram
        
        # List to store entropy values of each window
        entropy_values = []
        
        # Special case: file smaller than one window
        if len(raw_data) < self.WINDOW_SIZE:
            # Calculate entropy of the full file as a single window
            entropy = self._calculate_shannon_entropy(raw_data)
            entropy_values.append(entropy)
        else:
            # Normal sliding windows
            # numpy sliding window trick or just loop. Loop is fine for this scale.
            # Convert to numpy array once for faster slicing if needed, but bytes slicing is fast enough.
            for i in range(0, len(raw_data) - self.WINDOW_SIZE + 1, self.STEP_SIZE):
                window = raw_data[i:i + self.WINDOW_SIZE]
                entropy = self._calculate_shannon_entropy(window)
                entropy_values.append(entropy)
        
        if not entropy_values:
            return entropy_histogram
        
        # Convert to numpy array
        entropy_values_arr = np.array(entropy_values, dtype=np.float32)
        
        # Create entropy histogram
        # Entropy range: [0, 8] bits
        # Divide into NUM_BINS bins
        hist, _ = np.histogram(entropy_values_arr, bins=self.NUM_BINS, range=(0, 8))
        
        # Normalize by total number of windows
        entropy_histogram = hist.astype(np.float32) / len(entropy_values)
        
        return entropy_histogram
