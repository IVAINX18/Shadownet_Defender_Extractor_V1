import os
from pathlib import Path

# Base Directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Model Paths
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "best_model.onnx"
SCALER_PATH = MODELS_DIR / "scaler.pkl"

# Feature Configuration
FEATURE_DIMENSION = 2381

# Thresholds
MALWARE_THRESHOLD = 0.5
HIGH_CONFIDENCE_THRESHOLD = 0.85

# Logging
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "shadownet.log"
