"""
backend/app/api/routes/quarantine.py — Endpoints de cuarentena de archivos.

Expone POST /quarantine/file para aislar archivos detectados como amenazas
delegando la operación al QuarantineManager.
"""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Asegurar que el root del proyecto esté en el path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.api.dependencies.auth import get_current_user
from core.quarantine import QuarantineManager

router = APIRouter(prefix="/quarantine", tags=["quarantine"])


class QuarantineRequest(BaseModel):
    """Payload para solicitar cuarentena de un archivo."""
    file_path: str
    scan_id: str


@router.post(
    "/file",
    summary="Cuarentenar un archivo malicioso",
    description=(
        "Mueve el archivo especificado al directorio de cuarentena segura, "
        "elimina sus permisos de ejecución y guarda metadatos forenses."
    ),
    responses={
        200: {"description": "Operación completada (éxito o fallo con detalle)"},
        401: {"description": "Autenticación requerida"},
    },
)
async def quarantine_file(
    body: QuarantineRequest,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    """
    POST /quarantine/file — Aislar archivo en cuarentena.

    Requiere JWT válido. El actor de la operación se extrae del claim 'sub' del token.
    """
    manager = QuarantineManager()
    actor = user.get("sub") or user.get("id") or "api"

    result = manager.quarantine_file(
        Path(body.file_path),
        {"scan_id": body.scan_id},
        actor=actor,
    )

    return JSONResponse(
        content={
            "success": result.success,
            "quarantine_path": str(result.quarantine_path) if result.quarantine_path else None,
            "sha256": result.sha256,
            "meta_path": str(result.meta_path) if result.meta_path else None,
            "error": result.error,
        }
    )
