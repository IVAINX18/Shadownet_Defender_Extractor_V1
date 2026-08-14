"""
backend/app/api/routes/remediation.py — Endpoints de remediación de procesos.

Expone POST /remediation/terminate para terminar procesos maliciosos
detectados por el pipeline de escaneo, delegando al RemediationEngine.
Requiere autenticación JWT obligatoria.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Asegurar que el root del proyecto esté en el path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.api.dependencies.auth import get_current_user
from core.remediation import RemediationEngine
from utils.logger import setup_logger

logger = setup_logger("backend.routes.remediation")

router = APIRouter(prefix="/remediation", tags=["remediation"])


class TerminateRequest(BaseModel):
    """Payload para solicitar terminación de un proceso."""
    pid: int = Field(..., description="PID del proceso a terminar")
    scan_id: str = Field(..., description="ID del escaneo que originó la acción")
    reason: str = Field(
        default="malware_detected",
        description="Razón de la terminación (para auditoría)",
    )
    expected_exe: Optional[str] = Field(
        default=None,
        description="Ruta esperada del ejecutable (validación de seguridad extra)",
    )


@router.post(
    "/terminate",
    summary="Terminar un proceso malicioso",
    description=(
        "Termina un proceso detectado como malicioso. Incluye verificaciones "
        "de seguridad: rechaza PIDs protegidos del SO, verifica exe_path, "
        "y escala de SIGTERM a SIGKILL si es necesario."
    ),
    responses={
        200: {"description": "Operación completada (éxito o fallo con detalle)"},
        401: {"description": "Autenticación requerida"},
    },
)
async def terminate_process(
    body: TerminateRequest,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    """
    POST /remediation/terminate — Terminar proceso malicioso.

    Requiere JWT válido. Registra la identidad del operador para auditoría.
    """
    actor = user.get("sub") or user.get("id") or "api"
    logger.info(
        "Solicitud de terminación: pid=%d scan_id=%s reason=%s actor=%s",
        body.pid, body.scan_id, body.reason, actor,
    )

    engine = RemediationEngine()
    expected = Path(body.expected_exe) if body.expected_exe else None

    result = engine.terminate_process(
        pid=body.pid,
        reason=body.reason,
        scan_id=body.scan_id,
        expected_exe=expected,
    )

    return JSONResponse(
        content={
            "success": result.success,
            "pid": result.pid,
            "method": result.method,
            "error": result.error,
            "exe_path": result.exe_path,
            "scan_id": result.scan_id,
            "reason": result.reason,
            "timestamp": result.timestamp,
            "actor": actor,
        }
    )
