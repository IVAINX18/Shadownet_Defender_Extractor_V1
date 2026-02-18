import sys
from importlib import import_module
from typing import Any, Optional


MIN_PYTHON = (3, 11)
MAX_PYTHON_EXCLUSIVE = (3, 12)


def validate_python_version() -> None:
    """Enforces the supported runtime window for reproducible installs."""
    current = sys.version_info[:2]
    if current < MIN_PYTHON or current >= MAX_PYTHON_EXCLUSIVE:
        raise RuntimeError(
            "Unsupported Python version "
            f"{sys.version_info.major}.{sys.version_info.minor}. "
            "ShadowNet Defender requires Python >=3.11,<3.12. "
            "Create a compatible venv with: python3.11 -m venv .venv"
        )


def import_optional_dependency(
    module_name: str,
    *,
    install_profile: Optional[str] = None,
) -> Any:
    """
    Imports a dependency and raises a clear actionable message if unavailable.
    """
    try:
        return import_module(module_name)
    except ModuleNotFoundError as exc:
        profile_hint = (
            f"pip install -r {install_profile}"
            if install_profile
            else "pip install -r requirements/base.lock.txt"
        )
        raise RuntimeError(
            f"Missing dependency '{module_name}'. Install it with: {profile_hint}"
        ) from exc
