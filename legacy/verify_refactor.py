from core.engine import ShadowNetEngine
import sys
from pathlib import Path

def main():
    print("Initializing ShadowNet Engine...")
    try:
        engine = ShadowNetEngine()
    except Exception as e:
        print(f"Failed to initialize engine: {e}")
        sys.exit(1)
        
    sample_path = "samples/procexp64.exe"
    if not Path(sample_path).exists():
        print(f"Sample not found: {sample_path}")
        # Try to find any exe in samples
        samples = list(Path("samples").glob("*.exe"))
        if samples:
            sample_path = str(samples[0])
            print(f"Using alternative sample: {sample_path}")
        else:
            print("No samples found.")
            sys.exit(1)

    print(f"Scanning {sample_path}...")
    result = engine.scan_file(sample_path)
    
    print("\nScan Result:")
    print(f"File: {result['file']}")
    print(f"Label: {result['label']}")
    print(f"Score: {result['score']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Status: {result['status']}")
    
    if result['status'] == 'error':
        print(f"Error details: {result.get('error')}")
        sys.exit(1)
        
    print("\nRefactoring verification successful!")

if __name__ == "__main__":
    main()
