"""
⚠️  DEPRECATED — Este archivo ha sido reemplazado por backend/app/main.py

Para iniciar el nuevo backend:
    uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

Se mantiene como punto de entrada de compatibilidad.
"""
from __future__ import annotations

import warnings
warnings.warn(
    "main.py (raíz) está DEPRECATED. Usa 'uvicorn backend.app.main:app' en su lugar.",
    DeprecationWarning,
    stacklevel=1,
)

from backend.app.main import app  # noqa: F401
