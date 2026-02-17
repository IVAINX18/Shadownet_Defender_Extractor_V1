import sys
import os
import numpy as np
import joblib
from core.feature_extractor import extract_sorel_features

def main():
    sample_path = "samples/procexp.exe"
    scaler_path = "models/scaler.pkl"
    
    print(f"Testing SOREL extractor on {sample_path}...")
    
    if not os.path.exists(sample_path):
        print(f"Error: Sample {sample_path} not found.")
        return

    # 1. Extract features
    try:
        features = extract_sorel_features(sample_path)
        print(f"Extraction successful.")
        print(f"Feature vector shape: {features.shape}")
        
        if features.shape != (2381,):
            print(f"FAIL: Expected shape (2381,), got {features.shape}")
            return
        else:
            print("PASS: Shape is correct (2381,).")
            
        # Check for non-zero values in known blocks
        # ByteHistogram: 0-255
        # ByteEntropy: 256-511
        # General: 616-625
        # Header: 626-687
        # SectionInfo: 688-942
        
        byte_hist = features[0:256]
        byte_entropy = features[256:512]
        gen_feats = features[616:626]
        header_feats = features[626:688]
        section_feats = features[688:943]
        
        print(f"\n--- ByteHistogram Block ---")
        print(f"Sum: {byte_hist.sum():.6f}")
        
        print(f"\n--- ByteEntropy Block ---")
        print(f"Sum: {byte_entropy.sum():.6f}")
        
        print(f"\n--- General Block ---")
        print(f"General Block (first 5): {gen_feats[:5]}")

        print(f"\n--- Header Block ---")
        print(f"Header Block (first 5): {header_feats[:5]}")

        print(f"\n--- SectionInfo Block ---")
        print(f"Total Sections: {section_feats[0]}")
        print(f"Avg Entropy: {section_feats[4]:.4f}")
        print(f"First 5 entropy bins: {section_feats[15:20]}")
        
        if np.all(section_feats == 0):
             print("WARNING: SectionInfo features are all zero. Check if file has sections.")
        else:
             print("PASS: SectionInfo features contain non-zero values.")
        
        if np.all(gen_feats == 0):
             print("WARNING: General features are all zero. Something might be wrong.")
        else:
             print("PASS: General features contain non-zero values.")
             
        if np.all(header_feats == 0):
             print("WARNING: Header features are all zero. Something might be wrong.")
        else:
             print("PASS: Header features contain non-zero values.")
             
        # Test determinism: extract twice and compare
        print(f"\n--- Determinism Test ---")
        features2 = extract_sorel_features(sample_path)
        if np.array_equal(features, features2):
            print("PASS: Determinism verified (identical extractions).")
        else:
            print("FAIL: Extractions are not deterministic!")
            diff_count = np.sum(features != features2)
            print(f"  {diff_count} / {len(features)} values differ.")
             
    except Exception as e:
        print(f"Error during extraction: {e}")
        import traceback
        traceback.print_exc()
        return

    # 2. Test Scaler
    if not os.path.exists(scaler_path):
        print(f"Skipping scaler test: {scaler_path} not found.")
        return

    print(f"\nTesting Scaler transformation...")
    try:
        scaler = joblib.load(scaler_path)
        # Reshape for sklearn (1, 2381)
        features_reshaped = features.reshape(1, -1)
        
        scaled_features = scaler.transform(features_reshaped)
        print("Scaler transform successful.")
        print(f"Scaled features shape: {scaled_features.shape}")
        print(f"First 5 scaled values: {scaled_features[0][:5]}")
        print("PASS: Scaler is compatible.")
        
    except Exception as e:
        print(f"Error during scaler transform: {e}")
        print("FAIL: Scaler incompatibility.")

if __name__ == "__main__":
    main()
