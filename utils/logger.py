import logging
import logging.handlers
import sys
from rich.logging import RichHandler
from pathlib import Path
from configs.settings import LOG_DIR, LOG_FILE

# Maximum log file size before rotation (5 MB).
_MAX_LOG_BYTES = 5 * 1024 * 1024
# Number of rotated backup files to keep.
_BACKUP_COUNT = 3


def setup_logger(name: str = "ShadowNet", level: int = logging.INFO) -> logging.Logger:
    """
    Configures and returns a logger instance.
    Uses RichHandler for console output and RotatingFileHandler for file logs.
    """
    # Create logs directory if it doesn't exist
    if not LOG_DIR.exists():
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent adding handlers multiple times
    if logger.handlers:
        return logger

    # Console Handler (Rich)
    console_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_time=True,
        show_path=False
    )
    console_handler.setLevel(level)

    # File Handler with rotation (5 MB max, 3 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=_MAX_LOG_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
