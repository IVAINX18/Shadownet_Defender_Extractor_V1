"""
backend/app/services/llm_service.py — Servicio de explicación LLM con timeout.

Centralizo toda la lógica de comunicación con Ollama en un solo servicio.
Ejecuto la llamada al LLM en un thread con timeout configurable para que
nunca bloquee el flujo de escaneo. Si el LLM tarda más del timeout,
retorno un fallback inmediato.

La lógica real sigue delegando a core/llm/ que ya tiene el cliente
Ollama implementado con OpenAI SDK.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from pathlib import Path
from typing import Any, Dict, Optional

# Agrego la raíz del proyecto al path para importar los módulos de core/llm/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.llm.explanation_service import ExplanationService, ExplanationServiceConfig
from core.llm.prompt_builder import build_llm_prompt

logger = logging.getLogger("backend.llm_service")

# ---------------------------------------------------------------------------
# Timeout configurable para el LLM
# Leo de env para poder ajustar sin tocar código:
#   LLM_TIMEOUT=30  (segundos, default: 30)
# Un valor de 0 o negativo desactiva el timeout
# ---------------------------------------------------------------------------
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "30"))

# Pool de threads para ejecutar el LLM sin bloquear —
# uso max_workers=2 porque normalmente solo hay 1 request de explain activo
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="llm")

# ---------------------------------------------------------------------------
# Instancia lazy del servicio de explicación
# La creo en la primera llamada para evitar fallos al arrancar si Ollama
# no está disponible todavía (puede estar cargando un modelo pesado)
# ---------------------------------------------------------------------------
_explanation_service: Optional[ExplanationService] = None


def _get_service() -> ExplanationService:
    """
    Retorna la instancia compartida del ExplanationService.
    La inicializo lazy para no bloquear el arranque de la API.
    """
    global _explanation_service
    if _explanation_service is None:
        logger.info("Inicializando ExplanationService (primera vez)...")
        _explanation_service = ExplanationService(
            config=ExplanationServiceConfig(
                default_provider="ollama",
            )
        )
    return _explanation_service


def _call_llm(
    scan_data: Dict[str, Any],
    provider: Optional[str],
    model: Optional[str],
) -> Dict[str, Any]:
    """
    Ejecuta la llamada real al LLM (blocking).
    Se ejecuta dentro del ThreadPoolExecutor para poder aplicar timeout.
    """
    service = _get_service()
    return service.explain(scan_data, provider=provider, model=model)


def explain_scan_result(
    scan_data: Dict[str, Any],
    *,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Genera una explicación técnica de un resultado de escaneo usando el LLM.

    Ejecuto la llamada en un thread con timeout configurable:
    - Si responde a tiempo → retorno la explicación real
    - Si excede el timeout → retorno un fallback inmediato

    El escaneo NUNCA se bloquea esperando al LLM.

    Args:
        scan_data: Dict con el resultado del escaneo ML
                   (mínimo: label, score, confidence).
        provider:  Proveedor LLM a usar (default: "ollama").
        model:     Modelo específico (sobreescribe el default).

    Returns:
        Dict con:
          - provider: str — Proveedor usado
          - model: str — Modelo usado
          - response_text: str — Explicación generada (o fallback)
          - prompt_version: str — Versión del prompt
          - parsed_response: dict | None — JSON parseado del LLM
          - llm_status: str — "ok" | "timeout" | "error"

    No lanza excepciones: siempre retorna un dict válido.
    """
    effective_provider = provider or "ollama"
    effective_model = model or "default"

    logger.info(
        "Generando explicación → provider=%s, model=%s, label=%s, score=%s, timeout=%ds",
        effective_provider,
        effective_model,
        scan_data.get("label", scan_data.get("result", "?")),
        scan_data.get("score", scan_data.get("confidence", "?")),
        LLM_TIMEOUT,
    )

    start = time.time()

    # Si el timeout es <= 0, ejecuto sin límite de tiempo
    timeout_seconds = LLM_TIMEOUT if LLM_TIMEOUT > 0 else None

    try:
        future = _executor.submit(_call_llm, scan_data, provider, model)
        result = future.result(timeout=timeout_seconds)

        elapsed = time.time() - start
        result["llm_status"] = "ok"

        logger.info(
            "Explicación generada → provider=%s, model=%s, length=%d chars, time=%.1fs",
            result.get("provider"),
            result.get("model"),
            len(result.get("response_text", "")),
            elapsed,
        )

        return result

    except FuturesTimeout:
        elapsed = time.time() - start
        logger.warning(
            "LLM timeout → provider=%s, model=%s, timeout=%ds, elapsed=%.1fs",
            effective_provider,
            effective_model,
            LLM_TIMEOUT,
            elapsed,
        )
        # No cancelo el future — dejo que termine en background para no
        # corromper el estado del cliente OpenAI. Solo retorno el fallback.
        return {
            "provider": effective_provider,
            "model": effective_model,
            "response_text": "Explanation not available (timeout)",
            "prompt_version": "n/a",
            "parsed_response": None,
            "llm_status": "timeout",
        }

    except Exception as exc:
        elapsed = time.time() - start
        logger.error(
            "LLM error → provider=%s, model=%s, error=%s, time=%.1fs",
            effective_provider,
            effective_model,
            exc,
            elapsed,
        )
        return {
            "provider": effective_provider,
            "model": effective_model,
            "response_text": f"Explanation not available ({type(exc).__name__})",
            "prompt_version": "n/a",
            "parsed_response": None,
            "llm_status": "error",
        }


def get_prompt_preview(scan_data: Dict[str, Any]) -> str:
    """
    Retorna el prompt que se enviaría al LLM sin ejecutarlo.
    Útil para debugging y verificación.
    """
    return build_llm_prompt(scan_data)
