import pefile
import numpy as np
from typing import List, Dict

from extractors.base import FeatureBlock
from extractors.byte_histogram import ByteHistogram
from extractors.byte_entropy import ByteEntropy
from extractors.imports import ImportsFeatureBlock
from extractors.exports import ExportsFeatureBlock
from extractors.section_info import SectionInfoBlock
from extractors.header import HeaderFileInfo
from extractors.string_extractor import StringExtractorBlock
from extractors.general import GeneralFileInfo

class PEFeatureExtractor:
    """
    Main aggregator for PE feature extraction.
    Combines all feature blocks into a single compatible vector.
    """
    
    # Total dimension expected by the model/scaler (EMBER 2.0 standard)
    TOTAL_DIM = 2381
    
    def __init__(self):
        # Order matters! Must match training order.
        self.blocks: List[FeatureBlock] = [
            ByteHistogram(),       # 256
            ByteEntropy(),         # 256
            StringExtractorBlock(),# 104
            GeneralFileInfo(),     # 10
            HeaderFileInfo(),      # 62
            SectionInfoBlock(),    # 255
            ImportsFeatureBlock(), # 1280
            ExportsFeatureBlock()  # 128
        ]
        # Current sum = 2351. 
        # The scaler expects 2381. 
        # The remaining 30 features are padding (DataDirectories in some versions, but we use zeros here to match legacy).
        
    def extract_dict(self, file_path: str) -> Dict[str, np.ndarray]:
        """Returns features as a dictionary (useful for debugging)."""
        try:
            with open(file_path, "rb") as f:
                raw_data = f.read()
            pe = pefile.PE(data=raw_data)
        except Exception as e:
            print(f"Error parsing PE {file_path}: {e}")
            return {}

        results = {}
        for block in self.blocks:
            try:
                results[block.name] = block.extract(pe, raw_data)
            except Exception as e:
                print(f"Error extracting {block.name}: {e}")
                results[block.name] = np.zeros(block.dim, dtype=np.float32)
                
        pe.close()
        return results

    def extract(self, file_path: str) -> np.ndarray:
        """
        Extracts the full concatenated feature vector.
        """
        # Initialize full vector with zeros
        final_vector = np.zeros(self.TOTAL_DIM, dtype=np.float32)
        
        try:
            with open(file_path, "rb") as f:
                raw_data = f.read()
            pe = pefile.PE(data=raw_data)
        except Exception:
            return final_vector

        current_offset = 0
        for block in self.blocks:
            try:
                feats = block.extract(pe, raw_data)
                
                # Safety check for dimension
                if len(feats) != block.dim:
                    # Log error or resize? Resizing with zeros is safer for runtime.
                    padded = np.zeros(block.dim, dtype=np.float32)
                    min_len = min(len(feats), block.dim)
                    padded[:min_len] = feats[:min_len]
                    feats = padded
                
                end_offset = current_offset + block.dim
                final_vector[current_offset : end_offset] = feats
                current_offset = end_offset
                
            except Exception:
                # Leave as zeros if extraction fails
                current_offset += block.dim
                
        pe.close()
        # The remaining (2381 - 2351 = 30) features stay as 0.0
        return final_vector
