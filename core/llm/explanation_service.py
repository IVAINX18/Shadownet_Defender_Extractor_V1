from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol

from .ollama_client import OllamaClient, OllamaClientConfig
from .prompt_builder import build_llm_prompt

logger = logging.getLogger("shadownet.llm.service")


def _parse_json_response(response_text: str) -> Any | None:
    """
    Tries to parse model output as JSON.

    Accepts:
    - raw JSON text
    - markdown fenced JSON blocks (```json ... ```)

    Returns the parsed object when valid JSON is produced; otherwise returns None.
    """
    if not isinstance(response_text, str):
        return None

    text = response_text.strip()
    if not text:
        return None

    # 1) Fast path: raw JSON
    try:
        return json.loads(text)
    except Exception:
        pass

    # 2) Common LLM format: fenced JSON block
    fence_pattern = re.compile(
        r"```(?:json)?\s*(?P<body>[\s\S]*?)\s*```",
        re.IGNORECASE,
    )
    for match in fence_pattern.finditer(text):
        body = match.group("body").strip()
        if not body:
            continue
        try:
            return json.loads(body)
        except Exception:
            continue

    # 3) Last resort: parse largest object-like slice
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate)
        except Exception:
            return None

    return None


def _validate_llm_response(parsed: dict, scan_result: dict) -> dict:
    """
    Valida la coherencia entre el resultado del scan y la explicacion del LLM.

    Un LLM puede alucinar y describir una amenaza como de bajo riesgo aunque el
    scan_result indique CRITICAL. Esta funcion detecta esa inconsistencia y
    calcula una metrica de confianza basada en cuantos indicadores reales del
    scan se mencionan en la respuesta.

    Args:
        parsed:      Respuesta parseada del LLM (dict con threat_level, etc.).
        scan_result: Resultado del escaneo usado para construir el prompt.

    Returns:
        Dict con llm_inconsistent (bool) y llm_confidence (float 0-1).
    """
    import json as _json

    risk_level = scan_result.get("risk_level", "LOW").upper()
    threat_level = (parsed.get("threat_level") or "").lower()

    # Detectar inconsistencia: el LLM dice "no hay amenaza" cuando el scan dice CRITICAL/HIGH
    inconsistent = (
        risk_level in ("CRITICAL", "HIGH")
        and threat_level in ("none", "low")
    )

    # Calcular confianza por referencia a indicadores reales del scan
    # El LLM demuestra que analizo el resultado si menciona al menos un indicador concreto.
    real_indicators = [
        "overlay_ratio",
        "overlay_entropy",
        "yara",
        "injection",
        "persistence",
        "risk_score",
        "embedded_pe",
        "block_entropy",
    ]
    response_text = _json.dumps(parsed).lower()
    hits = sum(1 for ind in real_indicators if ind in response_text)
    # Normalizar sobre 3 hits como objetivo minimo para confianza maxima
    confidence = round(min(1.0, hits / 3.0), 2)

    return {"llm_inconsistent": inconsistent, "llm_confidence": confidence}


class LLMClient(Protocol):
    """
    Contrato minimo para clientes LLM.

    Permite reemplazar Ollama por OpenAI, Gemini o Claude sin cambiar la capa de servicio.
    """

    def generate(self, prompt: str, *, model: str | None = None) -> str:
        ...


@dataclass
class ExplanationServiceConfig:
    """
    Configuracion del servicio de explicacion.

    Lee OLLAMA_MODEL del entorno para determinar el modelo por defecto.
    """

    default_provider: str = "ollama"
    default_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    )


class ExplanationService:
    """
    Servicio de alto nivel que genera explicacion de resultados ML.

    Usa OllamaClient (OpenAI SDK) para comunicarse con Ollama,
    ya sea local o remoto mediante un endpoint HTTP compatible.
    """

    def __init__(
        self,
        *,
        config: Optional[ExplanationServiceConfig] = None,
        clients: Optional[Dict[str, LLMClient]] = None,
    ):
        self.config = config or ExplanationServiceConfig()
        self.clients = clients or {
            "ollama": OllamaClient(OllamaClientConfig(model=self.config.default_model)),
        }
        logger.info(
            "ExplanationService inicializado → provider=%s, model=%s",
            self.config.default_provider,
            self.config.default_model,
        )

    def register_client(self, provider: str, client: LLMClient) -> None:
        """
        Registra un nuevo proveedor LLM (futuro: OpenAI/Gemini/Claude).
        """
        self.clients[provider.strip().lower()] = client

    def explain(
        self,
        scan_result: Dict,
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict:
        """
        Genera explicacion basada en el JSON de escaneo.

        Incluye validacion post-LLM para detectar inconsistencias entre
        el veredicto del scan y la narrativa generada por el modelo de lenguaje.
        """
        resolved_provider = (provider or self.config.default_provider).strip().lower()
        client = self.clients.get(resolved_provider)
        if client is None:
            raise ValueError(
                f"Proveedor '{resolved_provider}' no soportado. "
                f"Disponibles: {sorted(self.clients.keys())}"
            )

        prompt = build_llm_prompt(scan_result)
        resolved_model = model or self.config.default_model
        response_text = client.generate(prompt, model=resolved_model)
        parsed_response = _parse_json_response(response_text)

        result = {
            "provider": resolved_provider,
            "model": resolved_model,
            "response_text": response_text,
            "prompt_version": "v1",
        }

        if parsed_response is not None:
            # Validar coherencia de la respuesta LLM antes de retornar (T-10)
            validation = _validate_llm_response(parsed_response, scan_result)
            parsed_response.update(validation)

            if validation.get("llm_inconsistent"):
                logger.warning(
                    "LLM inconsistente: risk_level=%s pero threat_level=%s "
                    "(llm_confidence=%.2f)",
                    scan_result.get("risk_level", ""),
                    parsed_response.get("threat_level", ""),
                    validation.get("llm_confidence", 0),
                )

            # Mantener compatibilidad hacia atras con response_text
            # mientras se ofrece la salida estructurada validada.
            result["parsed_response"] = parsed_response

        return result

