import logging
import sys
from rich.logging import RichHandler
from pathlib import Path
from configs.settings import LOG_DIR, LOG_FILE

def setup_logger(name: str = "ShadowNet", level: int = logging.INFO) -> logging.Logger:
    """
    Configures and returns a logger instance.
    Uses RichHandler for console output and FileHandler for file logs.
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
    
    # File Handler
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
