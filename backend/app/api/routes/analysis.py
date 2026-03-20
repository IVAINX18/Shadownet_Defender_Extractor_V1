"""
backend/app/api/routes/analysis.py — Endpoint de explicación LLM.

Defino la ruta POST /analysis/explain según el PRD.
Delego la lógica de explicación al llm_service (backend/app/services/)
y retorno la respuesta en formato estandarizado.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter, Depends

# Agrego la raíz del proyecto al path para importar módulos existentes
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.schemas.dto import ExplainRequest
from backend.app.utils.response import success_response, error_response
from backend.app.services.scan_service import scan_single_file
from backend.app.services.llm_service import explain_scan_result
from backend.app.integrations.supabase_client import save_scan_safe, sync_user
from backend.app.api.dependencies.auth import get_current_user
from utils.logger import setup_logger

logger = setup_logger("backend.routes.analysis")

router = APIRouter(prefix="/analysis", tags=["Análisis"])


@router.post(
    "/explain",
    summary="Generar explicación con LLM",
    description="Envía un resultado de escaneo a Ollama y genera una explicación técnica detallada.",
    responses={
        200: {"description": "Explicación generada exitosamente"},
        422: {"description": "Payload incompleto"},
        503: {"description": "Servicio LLM no disponible"},
    },
)
async def explain_scan(payload: ExplainRequest, user: dict = Depends(get_current_user)):
    """
    POST /analysis/explain — Explicación LLM del resultado de escaneo.

    Flujo:
    1. Recibo scan_result o file_path
    2. Si no hay scan_result, escaneo el archivo primero
    3. Llamo a llm_service.explain_scan_result()
    4. Retorno la explicación en formato estandarizado
    """
    scan_result_dict = payload.scan_result

    # Si no tengo scan_result, necesito al menos un file_path para escanear
    if scan_result_dict is None:
        if not payload.file_path:
            return error_response(
                "Proporciona 'scan_result' (preferido) o 'file_path' en el payload.",
                422,
            )

        # Escaneo el archivo primero usando scan_service
        try:
            file_path = Path(payload.file_path)
            scan_obj = scan_single_file(file_path)
            scan_result_dict = scan_obj.model_dump()
        except FileNotFoundError:
            return error_response(
                f"Archivo no encontrado: {payload.file_path}", 404
            )
        except Exception as exc:
            logger.error("Error escaneando archivo para explain: %s", exc)
            return error_response(f"Error escaneando archivo: {exc}", 500)

    # Inyecto datos del usuario autenticado
    scan_result_dict["user_id"] = user["id"]
    scan_result_dict["user_email"] = user["email"]

    # Genero la explicación usando llm_service directamente
    try:
        llm_result = explain_scan_result(
            scan_result_dict,
            provider=payload.provider,
            model=payload.model,
        )

        explanation_text = llm_result.get("response_text", "")

        response_data = {
            "scan_result": scan_result_dict,
            "explanation": explanation_text,
            "llm": {
                "provider": llm_result.get("provider", payload.provider),
                "model": llm_result.get("model", "unknown"),
                "prompt_version": llm_result.get("prompt_version", "v1"),
            },
        }

        # Sincronizo usuario y guardo en Supabase
        sync_user(user)
        if "file_name" in scan_result_dict:
            updated = dict(scan_result_dict)
            updated["explanation"] = explanation_text
            save_scan_safe(updated)

        return success_response(response_data)

    except Exception as exc:
        logger.error("Error generando explicación LLM: %s", exc)
        return error_response(f"Error generando explicación: {exc}", 503)
