from pathlib import Path
from typing import Dict, Any, Union
import time
import numpy as np

from extractors.extractor import PEFeatureExtractor
from models.inference import ShadowNetModel
from configs.settings import MODEL_PATH, SCALER_PATH, MALWARE_THRESHOLD, HIGH_CONFIDENCE_THRESHOLD
from utils.logger import setup_logger
from utils.runtime_checks import validate_python_version

logger = setup_logger(__name__)

class ShadowNetEngine:
    """
    Motor central de ShadowNet Defender. Orquesta el proceso de escaneo.

    📚 PARA JUNIORS — Patrón Facade (Fachada):

        Esta clase es la "puerta de entrada" al sistema. Ni la CLI, ni la API,
        ni ningún otro módulo necesitan saber cómo funcionan internamente los
        extractores o el modelo ONNX. Solo llaman a `engine.scan_file(path)`
        y reciben un diccionario con el resultado.

        El flujo interno es:
        1. PEFeatureExtractor → lee el archivo y genera un vector de 2381 dims
        2. ShadowNetModel    → normaliza el vector y ejecuta inferencia ONNX
        3. Labeling           → convierte el score numérico en etiqueta legible

        Si en el futuro cambiamos el modelo (ej: de LightGBM a PyTorch),
        solo modificamos esta clase y los módulos internos, sin afectar a
        la CLI ni a la API. Esto es Clean Architecture en acción.
    """
    
    def __init__(self):
        validate_python_version()
        self.extractor = PEFeatureExtractor()
        self.model = None
        self._load_model()
        
    def _load_model(self):
        """Initializes the model."""
        try:
            self.model = ShadowNetModel(MODEL_PATH, SCALER_PATH)
        except Exception as e:
            logger.critical(f"Engine failed to load model: {e}")
            # We don't raise here to allow the engine to start even if model is broken 
            # (e.g. for feature extraction only), but scan will fail.
            self.model = None

    def scan_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Scans a single file and returns the result.
        """
        file_path = Path(file_path)
        start_time = time.time()
        
        result = {
            "file": str(file_path),
            "status": "error",
            "score": -1.0,
            "label": "Unknown",
            "confidence": "Low",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "details": {}
        }

        if not file_path.exists():
            result["error"] = "File not found"
            return result

        try:
            logger.info(f"Scanning file: {file_path}")
            
            # 1. Feature Extraction
            logger.debug("Extracting features...")
            features = self.extractor.extract(str(file_path))
            
            # 2. Inference
            if self.model:
                logger.debug("Running inference...")
                score = self.model.predict(features)
                result["score"] = round(score, 4)
                
                # 3. Labeling
                if score >= MALWARE_THRESHOLD:
                    result["label"] = "MALWARE"
                    result["status"] = "detected"
                else:
                    result["label"] = "BENIGN"
                    result["status"] = "clean"
                    
                # Confidence
                if score > HIGH_CONFIDENCE_THRESHOLD or score < (1.0 - HIGH_CONFIDENCE_THRESHOLD):
                    result["confidence"] = "High"
                elif score > 0.6 or score < 0.4:
                    result["confidence"] = "Medium"
                else:
                    result["confidence"] = "Low"
            else:
                result["error"] = "Model not loaded"
                logger.error("Attempted scan without model loaded")

        except Exception as e:
            logger.error(f"Scan failed for {file_path}: {e}")
            result["error"] = str(e)
            
        elapsed = time.time() - start_time
        result["scan_time_ms"] = round(elapsed * 1000, 2)
        
        logger.info(f"Scan finished: {result['label']} (Score: {result['score']})")
        return result
