from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from .gemini_client import GeminiClient, GeminiClientConfig
from .groq_client import GroqClient, GroqClientConfig
from .prompt_builder import build_llm_prompt
from .template_explainer import TemplateExplainer

try:
    from openai import APIConnectionError, APIError, APITimeoutError, RateLimitError

    _LLM_TRANSPORT_ERRORS: tuple[type[BaseException], ...] = (
        RateLimitError,
        APITimeoutError,
        APIConnectionError,
        APIError,
    )
except ImportError:  # openai ausente: los clientes ya lanzan RuntimeError al construirse
    _LLM_TRANSPORT_ERRORS = ()  # type: ignore[assignment]

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
    Contrato minimo para clientes LLM en la nube (Groq, Gemini u otro
    OpenAI-compatible). Permite añadir un nuevo proveedor sin tocar explain().
    """

    def generate(self, prompt: str, *, model: str | None = None) -> str:
        ...


@dataclass
class ExplanationServiceConfig:
    """
    Configuracion del servicio de explicacion con cascada Tri-Fallover cloud.

    provider_order define la prelacion de fallover cuando un proveedor falla
    por cuota (429), red o timeout. Solo cloud: GROQ_MODEL
    (default openai/gpt-oss-20b) y GEMINI_MODEL (default gemini-3.5-flash-lite).
    `default_model` se mantiene por compatibilidad con clientes inyectados en
    tests/CLI que no usan groq/gemini; para groq/gemini se resuelve el modelo
    propio del proveedor.
    """

    default_provider: str = field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "groq").lower()
    )
    provider_order: List[str] = field(
        default_factory=lambda: [
            p.strip().lower()
            for p in os.getenv("LLM_PROVIDER_ORDER", "groq,gemini,template").split(",")
            if p.strip()
        ]
    )
    # Legacy/fallback para clientes inyectados en tests; no se usa para groq/gemini.
    default_model: str = field(
        default_factory=lambda: os.getenv("LLM_MODEL", os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"))
    )
    groq_model: str = field(
        default_factory=lambda: os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
    )
    gemini_model: str = field(
        default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    )


class ExplanationService:
    """
    Servicio de alto nivel que genera explicacion de resultados ML.

    Cascada Tri-Fallover: groq -> gemini -> template. Un provider explicito
    (parametro `provider` o `default_provider`) se intenta primero; si lanza
    un error de transporte/recursos (429, timeout, red, ValueError por falta
    de API key), se recorre el resto del provider_order sin reintentos, y el
    TemplateExplainer deterministico garantiza que la operacion siempre
    retorna un resultado valido. `_metadata.provider_used` identifica quien
    resolvio la peticion para UI y telemetria.
    """

    def __init__(
        self,
        *,
        config: Optional[ExplanationServiceConfig] = None,
        clients: Optional[Dict[str, LLMClient]] = None,
    ):
        self.config = config or ExplanationServiceConfig()
        # Clientos inyectados (tests / integraciones) tienen prioridad absoluta.
        self._clients: Dict[str, LLMClient] = {
            k.strip().lower(): v for k, v in (clients or {}).items()
        }
        # Los clientes por defecto se construyen de forma perezosa: evitar
        # abrir conexiones o validar entorno en el arranque del servicio.
        self._factories: Dict[str, callable] = {
            "groq": lambda: GroqClient(
                GroqClientConfig(model=self.config.groq_model)
            ),
            "gemini": lambda: GeminiClient(
                GeminiClientConfig(model=self.config.gemini_model)
            ),
            "template": lambda: TemplateExplainer(),
        }
        self._template = TemplateExplainer()
        logger.info(
            "ExplanationService inicializado → provider=%s, order=%s",
            self.config.default_provider,
            self.config.provider_order,
        )

    def _get_client(self, provider: str) -> Optional[LLMClient]:
        """Resuelve un cliente: inyectado primero, construido bajo demanda despues."""
        client = self._clients.get(provider)
        if client is not None:
            return client
        factory = self._factories.get(provider)
        if factory is None:
            return None
        try:
            client = factory()
        except Exception as exc:
            # Un factory roto (p.ej. base_url sin HTTPS en prod) no debe
            # tumbar el servicio: se registra y se hace fallover.
            logger.warning("No se pudo construir cliente %s: %s", provider, exc)
            return None
        self._clients[provider] = client
        return client

    @property
    def clients(self) -> Dict[str, LLMClient]:
        """Vista de clientes registrados (compat con introspeccion/tests previos)."""
        return self._clients

    def register_client(self, provider: str, client: LLMClient) -> None:
        """
        Registra (o reemplaza) un proveedor LLM. Permite añadir un 4º
        proveedor sin modificar explain() — principio abierto/cerrado.
        """
        self._clients[provider.strip().lower()] = client

    def _resolve_model(self, provider: str, model: Optional[str]) -> str:
        """Modelo explicito > modelo propio del provider > default legacy."""
        if model:
            return model
        if provider == "groq":
            return self.config.groq_model
        if provider == "gemini":
            return self.config.gemini_model
        # Clientes inyectados / template usan default_model por compat.
        return self.config.default_model

    def _try_provider(
        self,
        scan_result: Dict,
        provider: str,
        model: Optional[str],
    ) -> Dict:
        """Intenta un proveedor unico. Lanza en error de recurso/transporte.

        Nota de compatibilidad: si el cliente responde pero el texto no es
        JSON parseable, se retorna el resultado sin `parsed_response` (igual
        que antes) en lugar de hacer fallover — un LLM que contesta no es un
        proveedor caido, y silenciarlo cambiaria la semantica existente.
        """
        client = self._get_client(provider)
        if client is None:
            raise LookupError(f"Proveedor '{provider}' no disponible.")

        prompt = build_llm_prompt(scan_result)
        resolved_model = self._resolve_model(provider, model)
        response_text = client.generate(prompt, model=resolved_model)
        parsed_response = _parse_json_response(response_text)

        result: Dict[str, Any] = {
            "provider": provider,
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

            result["parsed_response"] = parsed_response

        return result

    def _fallback_template(self, scan_result: Dict, last_error: Optional[BaseException]) -> Dict:
        """Ultimo recurso deterministico: nunca lanza excepcion ni usa red."""
        parsed_template = self._template.explain_from_scan_result(scan_result)
        return {
            "provider": "template",
            "model": "rule-engine-v1",
            "response_text": json.dumps(parsed_template, ensure_ascii=False),
            "parsed_response": parsed_template,
            "prompt_version": "v1_fallback",
            "_metadata": {
                "provider_used": "template",
                "fallover": last_error is not None,
                "last_error": str(last_error)[:300] if last_error else None,
            },
        }

    def explain(
        self,
        scan_result: Dict,
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict:
        """
        Genera explicacion con cascada groq -> gemini -> template.

        El provider solicitado (o default_provider) se intenta primero; ante
        errores de recurso (429/quota, timeout, red, falta de API key) se
        recorre provider_order excluyendo al ya intentado. Template nunca
        falla, por lo que explain() siempre retorna un dict utilizable.
        """
        primary = (provider or self.config.default_provider).strip().lower()
        # Cadena a intentar: primary primero, luego el resto del orden configurado.
        chain = [primary] + [p for p in self.config.provider_order if p != primary]

        last_error: Optional[BaseException] = None
        errors: Dict[str, str] = {}

        for candidate in chain:
            if candidate == "template":
                return self._fallback_template(scan_result, last_error)
            try:
                result = self._try_provider(scan_result, candidate, model)
                result["_metadata"] = {
                    "provider_used": candidate,
                    "fallover": last_error is not None,
                    "errors": errors or None,
                }
                return result
            except (
                *_LLM_TRANSPORT_ERRORS,
                ValueError,
                RuntimeError,
                LookupError,
            ) as exc:
                # 429 y fallos de red/keys: saltar de inmediato, sin reintento.
                is_quota = isinstance(exc, RateLimitError) or "429" in str(exc)
                logger.warning(
                    "Fallo en proveedor '%s'%s (%s): %s — conmutando al siguiente...",
                    candidate,
                    " (cuota/rate limit)" if is_quota else "",
                    type(exc).__name__,
                    exc,
                )
                errors[candidate] = f"{type(exc).__name__}: {str(exc)[:200]}"
                last_error = exc
                continue

        # Inalcanzable en la practica (template corta el loop); defensa propia.
        return self._fallback_template(scan_result, last_error)

