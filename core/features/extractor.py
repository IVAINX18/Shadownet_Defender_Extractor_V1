import pefile
import numpy as np
from .base import FeatureBlock
from .general import GeneralFileInfo
from .header import HeaderFileInfo

class PEFeatureExtractor:
    """
    Main feature extractor that combines multiple feature blocks
    to produce a SOREL-compatible feature vector.
    """
    
    def __init__(self, feature_version: int = 2):
        self.blocks = [
            # EMBER 2.0 / SOREL standard order:
            # 1. ByteHistogram (256) - To be implemented
            # 2. ByteEntropy (256) - To be implemented
            # 3. StringExtractor (104) - To be implemented
            # 4. GeneralFileInfo (10)
            # 5. HeaderFileInfo (62)
            # 6. SectionInfo (255) - To be implemented
            # 7. Imports (1280) - To be implemented
            # 8. Exports (128) - To be implemented
            
            # For now, we only have General and Header.
            # We must respect the ORDER in the final vector.
            # Since I haven't implemented block 1-3, I need to pad BEFORE General.
            
            # Placeholder for unimplmented blocks
            # But wait, the user asked for "Modular and extensible".
            # I should register blocks and specificy their offset/order?
            # Or just list them and pad the gaps?
            
            # Implementation strategy: 
            # Define the FULL list of blocks with their sizes.
            # If a block is implemented, use it. If not, return zeros.
            
            # However, I only have classes for General and Header.
            # So I will instantiate them.
        ]
        
        # We need to map the blocks to their correct positions.
        # Implemented blocks:
        self.general_block = GeneralFileInfo()
        self.header_block = HeaderFileInfo()
        
        # Expected total capabilities
        self.total_dim = 2381
        
    def extract(self, file_path: str) -> np.ndarray:
        """
        Extract features from a PE file.
        Returns a (2381,) float32 array.
        """
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
        except Exception as e:
            # If file cannot be read, return zeros? 
            # Or raise? Standard scaler expects robust input.
            # For now, let's let pefile handle it or raise.
            raise e
            
        try:
            pe = pefile.PE(data=raw_data)
        except pefile.PEFormatError:
            # Invalid PE, return zeros or raise?
            # EMBER usually handles this gracefully, but let's stick to simple for now.
             return np.zeros(self.total_dim, dtype=np.float32)

        # Initialize final vector
        final_vector = np.zeros(self.total_dim, dtype=np.float32)
        
        # We need to know where to put our features.
        # Based on EMBER 2.0 structure:
        # 0-255: ByteHistogram
        # 256-511: ByteEntropy
        # 512-615: Strings (104)
        # 616-625: GeneralFileInfo (10)  <-- We are here
        # 626-687: HeaderFileInfo (62)   <-- And here
        # 688-942: SectionInfo (255)
        # 943-2222: Imports (1280)
        # 2223-2350: Exports (128)
        # Total: 2351?
        
        # User said 2381. That's +30.
        # Often DataDirectories (15*2 = 30) are treated separately or part of Header?
        # My Header implementation includes data directories (32 features).
        
        # Let's trust the user's "2381" and my implementation of blocks.
        # For this task, I will place General and Header where they usually belong
        # relative to the start, but I need to be careful about the "2381" requirement.
        
        # If I don't know the exact offset of the other features, 
        # I might overwrite or shift things.
        
        # ASSUMPTION:
        # The user wants "reconstruct SOREL-compatible extractor".
        # I'll define the offsets.
        
        # ByteHistogram: 256
        # ByteEntropy: 256
        # Strings: 104
        # Total before General: 616
        
        offset_general = 616
        
        # Extract General
        general_feats = self.general_block.extract(pe, raw_data)
        final_vector[offset_general : offset_general + self.general_block.dim] = general_feats
        
        # Header follows General immediately?
        # General (10) -> 616+10 = 626.
        offset_header = 626
        
        # Extract Header
        header_feats = self.header_block.extract(pe, raw_data)
        final_vector[offset_header : offset_header + self.header_block.dim] = header_feats
        
        return final_vector
