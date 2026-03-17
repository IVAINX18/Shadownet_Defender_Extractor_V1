"""
backend/app/services/llm_service.py — Servicio de explicación LLM.

Centralizo toda la lógica de comunicación con Ollama (local o remoto)
en un solo servicio desacoplado. Reemplazo el uso directo de
scripts heredados por una interfaz limpia dentro de backend/app/.

La lógica real sigue delegando a core/llm/ que ya tiene el cliente
Ollama implementado correctamente con OpenAI SDK.
"""

from __future__ import annotations

import logging
import sys
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


def explain_scan_result(
    scan_data: Dict[str, Any],
    *,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Genera una explicación técnica de un resultado de escaneo usando el LLM.

    Orquesto el flujo completo:
    1. Obtengo el ExplanationService (lazy init)
    2. Delego la generación de prompt y llamada al LLM a core/llm/
    3. Retorno la respuesta estructurada

    Args:
        scan_data: Dict con el resultado del escaneo ML
                   (mínimo: label, score, confidence).
        provider:  Proveedor LLM a usar (default: "ollama").
        model:     Modelo específico (sobreescribe el default).

    Returns:
        Dict con:
          - provider: str — Proveedor usado
          - model: str — Modelo usado
          - response_text: str — Explicación completa generada
          - prompt_version: str — Versión del prompt
          - parsed_response: dict | None — JSON parseado (si el LLM lo retorna)

    Raises:
        RuntimeError: Si Ollama no está disponible o falla la conexión.
        ValueError: Si el proveedor no está registrado.
    """
    service = _get_service()

    logger.info(
        "Generando explicación → provider=%s, model=%s, label=%s, score=%s",
        provider or "ollama",
        model or "default",
        scan_data.get("label", scan_data.get("result", "?")),
        scan_data.get("score", scan_data.get("confidence", "?")),
    )

    result = service.explain(scan_data, provider=provider, model=model)

    logger.info(
        "Explicación generada → provider=%s, model=%s, length=%d chars",
        result.get("provider"),
        result.get("model"),
        len(result.get("response_text", "")),
    )

    return result


def get_prompt_preview(scan_data: Dict[str, Any]) -> str:
    """
    Retorna el prompt que se enviaría al LLM sin ejecutarlo.
    Útil para debugging y verificación.
    """
    return build_llm_prompt(scan_data)
