from core.feature_extractor import extract_basic_pe_features
from core.inference import ShadowNetModel

MODEL_PATH = "models/best_model.onnx"
SCALER_PATH = "models/scaler.pkl"

model = ShadowNetModel(MODEL_PATH, SCALER_PATH)

def scan_file(file_path: str):
    try:
        features = extract_basic_pe_features(file_path)
        score = model.predict(features)

        label = "Malware" if score >= 0.5 else "Benign"

        return {
            "file": file_path,
            "score": round(score, 4),
            "label": label
        }
    except Exception as e:
        return {
            "file": file_path,
            "error": str(e)
        }
