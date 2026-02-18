import numpy as np
import joblib
from pathlib import Path
from typing import Optional, Any
from utils.logger import setup_logger
from utils.runtime_checks import validate_python_version, import_optional_dependency

validate_python_version()
ort = import_optional_dependency(
    "onnxruntime",
    install_profile="requirements/base.lock.txt",
)

logger = setup_logger(__name__)

class ShadowNetModel:
    """
    Wrapper for ShadowNet Defender ONNX model.
    Handles loading, preprocessing (scaling), and inference.
    """

    def __init__(self, model_path: Path, scaler_path: Path):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.session: Optional[Any] = None
        self.scaler = None
        self.input_name = None
        
        self.load()

    def load(self):
        """Loads the ONNX model and the scaler."""
        try:
            if not self.model_path.exists():
                raise FileNotFoundError(f"Model not found at {self.model_path}")
            if not self.scaler_path.exists():
                raise FileNotFoundError(f"Scaler not found at {self.scaler_path}")

            logger.info(f"Loading model from {self.model_path}...")
            self.session = ort.InferenceSession(str(self.model_path))
            self.input_name = self.session.get_inputs()[0].name
            
            logger.info(f"Loading scaler from {self.scaler_path}...")
            self.scaler = joblib.load(self.scaler_path)
            
            logger.info("Model and scaler loaded successfully.")
            
        except Exception as e:
            logger.critical(f"Failed to load model/scaler: {e}")
            raise

    def predict(self, features: np.ndarray) -> float:
        """
        Performs inference on the given feature vector.
        
        Args:
            features: 1D numpy array of features.
            
        Returns:
            Malware probability score [0.0 - 1.0].
        """
        try:
            # Reshape for single sample
            features = features.reshape(1, -1)
            
            # Scale features
            if self.scaler:
                scaled_features = self.scaler.transform(features)
            else:
                logger.warning("Scaler not loaded, using raw features!")
                scaled_features = features

            # Run inference
            inputs = {self.input_name: scaled_features.astype(np.float32)}
            outputs = self.session.run(None, inputs)
            
            output_tensor = outputs[0]
            # logger.debug(f"Model output shape: {output_tensor.shape}")
            
            # Robustly extract score
            # Expected shapes: (1, 1) -> score is [0,0]
            # (1,) -> score is [0]
            # (1, 2) -> score is [0, 1] (binary classification prob)
             
            if output_tensor.size == 1:
                score = float(output_tensor.item())
            elif output_tensor.ndim == 2 and output_tensor.shape[1] == 2:
                # Assuming index 1 is the positive class (Malware)
                score = float(output_tensor[0, 1])
            else:
                # Fallback: try to take the last element or the largest
                # logger.warning(f"Unexpected output shape {output_tensor.shape}, trying flat index 0")
                score = float(output_tensor.flatten()[0])
            
            return score
            
        except Exception as e:
            logger.error(f"Inference error: {e}")
            raise
