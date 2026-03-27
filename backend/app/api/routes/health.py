"""
backend/app/api/routes/health.py — Endpoint de salud del sistema.

Defino GET /health para verificar el estado del backend y sus
componentes según el PRD sección 4.3.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.config import MAX_UPLOAD_MB
from backend.app.services.scan_service import get_engine
from backend.app.utils.response import success_response

router = APIRouter(tags=["Sistema"])


@router.get(
    "/health",
    summary="Estado del backend",
    description="Verifica que el backend esté funcionando y reporta el estado del modelo ML.",
)
def health():
    """
    GET /health — Estado del backend.

    Reporto:
    - Estado general del servicio
    - Estado del modelo ML (loaded/not_loaded)
    """
    try:
        engine = get_engine()
        model_state = "loaded" if engine.model is not None else "not_loaded"
    except Exception:
        model_state = "error"

    return success_response({
        "status": "ok",
        "model": model_state,
        "version": "1.0.0",
        "max_upload_mb": MAX_UPLOAD_MB,
    })
