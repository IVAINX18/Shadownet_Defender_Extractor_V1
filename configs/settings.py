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

# ── Nuevas variables de entorno con defaults seguros ─────────────────────────
QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", str(Path.home() / ".shadownet" / "quarantine")))
ANALYSIS_TIMEOUT_SECONDS = int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "60"))
BEHAVIORAL_SHIELD_TIMEOUT_SECONDS = int(os.getenv("BEHAVIORAL_SHIELD_TIMEOUT_SECONDS", "2"))
MAX_UPLOAD_MB = max(1, int(os.getenv("MAX_UPLOAD_MB", "50")))
RATE_LIMIT_SCANS_PER_MINUTE = int(os.getenv("RATE_LIMIT_SCANS_PER_MINUTE", "20"))
SUPABASE_INCIDENTS_TABLE = os.getenv("SUPABASE_INCIDENTS_TABLE", "incidents")
EXTRACTOR_TIMEOUT_SECONDS = int(os.getenv("EXTRACTOR_TIMEOUT_SECONDS", "15"))


def validate_paths(logger) -> None:
    """Valida que MODEL_PATH y SCALER_PATH existan en disco.
    Registra WARNING en logs si no existen."""
    for p in (MODEL_PATH, SCALER_PATH):
        if not p.exists():
            logger.warning("Archivo requerido no encontrado: %s", p)


def log_config(logger) -> None:
    """Loguea la configuración activa enmascarando claves secretas."""
    _MASKED_KEYS = {"SUPABASE_KEY", "SUPABASE_JWT_SECRET"}
    _RELEVANT_PREFIXES = (
        "SHADOWNET_", "SUPABASE_", "N8N_", "MAX_", "RATE_",
        "QUARANTINE_", "ANALYSIS_", "BEHAVIORAL_",
    )
    for key, value in os.environ.items():
        if any(key.startswith(prefix) for prefix in _RELEVANT_PREFIXES):
            display = "***" if key in _MASKED_KEYS else value
            logger.info("Config: %s = %s", key, display)
