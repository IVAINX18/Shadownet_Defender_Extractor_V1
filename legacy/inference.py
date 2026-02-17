import onnxruntime as ort
import numpy as np
import joblib

class ShadowNetModel:
    def __init__(self, model_path, scaler_path):
        self.session = ort.InferenceSession(model_path)
        self.scaler = joblib.load(scaler_path)
        self.input_name = self.session.get_inputs()[0].name

    def predict(self, features: np.ndarray) -> float:
        features = features.reshape(1, -1)
        features = self.scaler.transform(features)
        outputs = self.session.run(None, {self.input_name: features.astype(np.float32)})
        return float(outputs[0][0])
