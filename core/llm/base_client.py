"""
core/llm/base_client.py — Esqueleto común para clientes LLM en la nube vía OpenAI SDK.

Extrae el 60% de duplicación entre GroqClient y GeminiClient (y el antiguo
cloud): configuracion, validacion, creacion del cliente OpenAI,
construcción de mensajes forenses, llamada con response_format json_object y
extracción de contenido.

Diseño:
- LLMClientConfig es la base genérica; subclases aportan defaults de entorno.
- BaseLLMClient concentra el flujo valido; subclases solo definen constantes
  y, si hace falta, override de generate() (Gemini: fallback 503 interno).

Seguridad: valida HTTPS en producción (OWASP ASVS 9.2.1) y nunca loguea API keys.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from openai import (
        APIConnectionError,
        APIError,
        APITimeoutError,
        OpenAI,
        RateLimitError,
    )
except ImportError:  # pragma: no cover — degradación sin dependencia
    OpenAI = None  # type: ignore[assignment]
    APIConnectionError = APIError = APITimeoutError = RateLimitError = Exception  # type: ignore[assignment,misc]

# Prompt forense único para toda la cascada — el LLM explica resultados
# ya calculados, no detecta malware. Debe responder solo JSON.
FORENSIC_SYSTEM_PROMPT = (
    "Eres el motor de analisis forense de malware de ShadowNet Defender. "
    "Explicas resultados ya calculados; NO detectas malware. "
    "Responde UNICAMENTE con JSON valido segun las instrucciones."
)


@dataclass
class LLMClientConfig:
    """Configuración genérica para un cliente OpenAI-compatible en la nube."""

    api_key: str = ""
    base_url: str = ""
    model: str = ""
    timeout_seconds: float = 10.0
    temperature: float = 0.2
    max_tokens: Optional[int] = 1024


class BaseLLMClient:
    """Base para clientes Groq/Gemini — concentra validación y flujo común."""

    def __init__(
        self,
        config: LLMClientConfig,
        *,
        provider_name: str,
        api_key_env: str,
    ) -> None:
        if OpenAI is None:  # pragma: no cover
            raise RuntimeError(
                f"El paquete 'openai' es requerido para {provider_name}. "
                "Instalalo con: pip install openai>=1.0.0"
            )

        self.config = config
        self._provider_name = provider_name
        self._api_key_env = api_key_env
        self._logger = logging.getLogger(f"shadownet.llm.{provider_name.lower()}")

        if not self.config.api_key:
            self._logger.warning(
                "%s no configurada — %s fallara con ValueError al generar "
                "y ExplanationService conmutara al siguiente proveedor.",
                api_key_env,
                provider_name,
            )

        # En producción el transporte debe ser HTTPS para proteger la API key.
        if os.getenv("ENVIRONMENT", "dev").lower() == "prod" and not self.config.base_url.lower().startswith(
            "https://"
        ):
            raise RuntimeError(
                f"{provider_name} base_url debe usar HTTPS en produccion para proteger la API key."
            )

        self._client = OpenAI(
            api_key=self.config.api_key or f"missing_{provider_name.lower()}_key",
            base_url=self.config.base_url,
            timeout=float(self.config.timeout_seconds),
        )
        self._logger.info(
            "%s inicializado -> base_url=%s, model=%s, timeout=%.1fs",
            provider_name,
            self.config.base_url,
            self.config.model,
            float(self.config.timeout_seconds),
        )

    # -- helpers protegidos -------------------------------------------------

    def _build_messages(self, prompt: str) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": FORENSIC_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

    def _extract_content(self, response: Any) -> str:
        content = (response.choices[0].message.content or "").strip()
        if not content:
            raise RuntimeError(f"{self._provider_name} devolvio una respuesta vacia.")
        return content

    # -- API pública --------------------------------------------------------

    def generate(self, prompt: str, *, model: Optional[str] = None) -> str:
        """Envia el prompt y devuelve el texto JSON de la explicacion.

        Propaga RateLimitError / timeout / red sin envolver para que
        ExplanationService distinga el fallover recuperable del fallo duro.
        """
        target_model = (model or self.config.model).strip()

        if not self.config.api_key:
            raise ValueError(f"{self._api_key_env} es requerida para explicar con {self._provider_name}.")

        messages = self._build_messages(prompt)

        try:
            response = self._client.chat.completions.create(
                model=target_model,
                messages=messages,  # type: ignore[arg-type]
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                response_format={"type": "json_object"},
            )
        except RateLimitError as exc:
            self._logger.warning("%s rate limit (HTTP 429): %s", self._provider_name, exc)
            raise
        except APITimeoutError as exc:
            self._logger.warning(
                "%s timeout (%.1fs): %s", self._provider_name, float(self.config.timeout_seconds), exc
            )
            raise
        except APIConnectionError as exc:
            self._logger.warning("%s error de conexion: %s", self._provider_name, exc)
            raise
        except APIError as exc:
            self._logger.error(
                "%s APIError status=%s: %s", self._provider_name, getattr(exc, "status_code", "?"), exc
            )
            raise

        return self._extract_content(response)
