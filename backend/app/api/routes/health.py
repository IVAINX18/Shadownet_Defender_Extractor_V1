"""
backend/app/api/routes/health.py — Endpoint de salud del sistema (extendido).

GET /health verifica el estado del backend y todos sus componentes.
No requiere autenticación JWT (público).

Mejoras de auditoría (Tarea 19):
  19.1 — _check_components(): onnx_model, yara_scanner, supabase, n8n, psutil, offline_queue_size
  19.2 — _compute_pipeline_mode(): full / degraded / minimal
  19.3 — HTTP 503 si componente crítico (onnx_model o yara_scanner) está degradado
  19.4 — Sin autenticación JWT
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter
from fastapi.responses import JSONResponse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.config import MAX_UPLOAD_MB
from backend.app.utils.response import success_response

router = APIRouter(tags=["Sistema"])


# ---------------------------------------------------------------------------
# 19.1 — Verificación de componentes
# ---------------------------------------------------------------------------

def _check_onnx() -> str:
    """Verifica si el modelo ONNX está cargado: 'loaded' | 'missing'."""
    try:
        from backend.app.services.scan_service import get_engine
        engine = get_engine()
        return "loaded" if engine.model is not None else "missing"
    except Exception:
        return "missing"


def _check_yara() -> str:
    """Verifica si el scanner YARA está disponible: 'available' | 'unavailable'."""
    try:
        from backend.app.services.scan_service import get_engine
        engine = get_engine()
        scanner = getattr(engine, "_yara_scanner", None)
        if scanner is not None and getattr(scanner, "is_available", False):
            return "available"
        return "unavailable"
    except Exception:
        return "unavailable"


def _check_supabase() -> str:
    """Verifica conexión a Supabase: 'connected' | 'disconnected' | 'not_configured'."""
    supabase_key = os.getenv("SUPABASE_KEY", "").strip()
    if not supabase_key:
        return "not_configured"
    try:
        from supabase import create_client
        from backend.app.integrations.supabase_client import SUPABASE_URL
        client = create_client(SUPABASE_URL, supabase_key)
        # Intentar una operación mínima
        client.table("scan_results").select("id").limit(1).execute()
        return "connected"
    except ImportError:
        return "not_configured"
    except Exception:
        return "disconnected"


def _check_n8n() -> str:
    """Verifica si N8N está habilitado: 'enabled' | 'disabled'."""
    n8n_enabled = os.getenv("N8N_ENABLED", "").strip().lower()
    if n8n_enabled in ("1", "true", "yes", "on"):
        return "enabled"
    return "disabled"


def _check_psutil() -> str:
    """Verifica si psutil está disponible: 'available' | 'unavailable'."""
    try:
        import psutil
        return "available"
    except ImportError:
        return "unavailable"


def _check_offline_queue() -> int:
    """Retorna el tamaño de la cola offline."""
    try:
        from backend.app.services.offline_service import get_queue_size
        return get_queue_size()
    except Exception:
        return 0


def _check_components() -> Dict[str, Any]:
    """19.1 — Verifica el estado de todos los componentes del sistema."""
    return {
        "onnx_model": _check_onnx(),
        "yara_scanner": _check_yara(),
        "supabase": _check_supabase(),
        "n8n": _check_n8n(),
        "psutil": _check_psutil(),
        "offline_queue_size": _check_offline_queue(),
    }


# ---------------------------------------------------------------------------
# 19.2 — Modo del pipeline
# ---------------------------------------------------------------------------

def _compute_pipeline_mode(components: Dict[str, Any]) -> str:
    """
    Determina el modo operativo del pipeline:
    - 'full': todos los componentes críticos operativos
    - 'degraded': algún componente no crítico fallando
    - 'minimal': componentes críticos fallando
    """
    onnx_ok = components.get("onnx_model") == "loaded"
    yara_ok = components.get("yara_scanner") == "available"

    if onnx_ok and yara_ok:
        # Verificar si todos los demás también están OK
        supabase_ok = components.get("supabase") in ("connected", "not_configured")
        psutil_ok = components.get("psutil") == "available"
        if supabase_ok and psutil_ok:
            return "full"
        return "degraded"

    if not onnx_ok and not yara_ok:
        return "minimal"

    return "degraded"


# ---------------------------------------------------------------------------
# 19.3/19.4 — Endpoint GET /health (sin JWT)
# ---------------------------------------------------------------------------

@router.get(
    "/health",
    summary="Estado del backend",
    description=(
        "Verifica que el backend esté funcionando y reporta el estado de "
        "todos los componentes. No requiere autenticación."
    ),
)
def health():
    """
    GET /health — Estado extendido del backend (sin JWT).

    19.3 — Retorna HTTP 503 si un componente crítico está degradado.
    19.4 — No requiere autenticación JWT.
    """
    components = _check_components()
    mode = _compute_pipeline_mode(components)

    critical_degraded = (
        components["onnx_model"] == "missing"
        or components["yara_scanner"] == "unavailable"
    )

    status_code = 503 if critical_degraded else 200
    status_label = "degraded" if critical_degraded else "ok"

    return JSONResponse(
        status_code=status_code,
        content={
            "status": "success",
            "data": {
                "status": status_label,
                "pipeline_mode": mode,
                "components": components,
                "version": "2.0.0",
                "max_upload_mb": MAX_UPLOAD_MB,
            },
        },
    )


# ---------------------------------------------------------------------------
# Tri-Fallover — Endpoint GET /health/llm-providers (sin JWT)
#
# La UI de Electron lo consulta para saber qué proveedores están configurados
# y mostrar el badge del proveedor que resolvió cada explicación. Seguridad:
# SOLO expone booleans y nombres de modelo — jamás valores de API keys.
# ---------------------------------------------------------------------------

@router.get(
    "/health/llm-providers",
    summary="Proveedores LLM disponibles",
    description=(
        "Reporta la cascada Tri-Fallover configurada (groq -> gemini -> "
        "template) y qué proveedores tienen API key disponible. No expone "
        "claves, solo disponibilidad."
    ),
)
def health_llm_providers():
    """Disponibilidad de proveedores para la UI (autodetección de keys)."""
    order = [
        p.strip().lower()
        for p in os.getenv("LLM_PROVIDER_ORDER", "groq,gemini,template").split(",")
        if p.strip()
    ]
    return success_response(
        {
            "order": order,
            "available": {
                "groq": bool(os.getenv("GROQ_API_KEY")),
                "gemini": bool(os.getenv("GEMINI_API_KEY")),
                "ollama": True,  # intentable siempre; healthcheck local aparte
                "template": True,  # offline determinístico, nunca falta
            },
            "models": {
                "groq": os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
                "gemini": os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite"),
                "ollama": os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
            },
        }
    )
