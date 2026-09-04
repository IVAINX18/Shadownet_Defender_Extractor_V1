"""
core/llm/groq_client.py — Cliente Groq API vía endpoint OpenAI-compatible.

Provider primario de la cascada Tri-Fallover (groq -> gemini -> template).
Groq expone https://api.groq.com/openai/v1 compatible con el SDK oficial
`openai`, por lo que se reutiliza la misma dependencia que OllamaClient sin
añadir paquetes nuevos a requirements/base.in (decisión de supply-chain).

Modelo por defecto: openai/gpt-oss-20b. Validado 2026-09-01 contra
GET /openai/v1/models para esta organización: es el único modelo Production
generativo rápido habilitado (1000 tok/s, 131K ctx, json_mode + structured_outputs).
Llama 3.1/3.3 NO están disponibles para esta API key — no reintroducirlos.

Contrato de errores: RateLimitError (429/cuota) y errores de red/timeout se
propagan SIN envolver para que ExplanationService distinga el fallover
recuperable (saltar de proveedor) del fallo duro.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

try:
    from openai import (
        OpenAI,
        APIConnectionError,
        APIError,
        APITimeoutError,
        RateLimitError,
    )
except ImportError:
    OpenAI = None  # type: ignore[assignment]
    APIConnectionError = APIError = APITimeoutError = RateLimitError = Exception  # type: ignore[assignment,misc]

logger = logging.getLogger("shadownet.llm.groq")

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"


@dataclass
class GroqClientConfig:
    """Configuración del cliente Groq (100% sobrescribible para tests)."""

    api_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", ""))
    base_url: str = GROQ_BASE_URL
    model: str = field(
        default_factory=lambda: os.getenv("GROQ_MODEL") or DEFAULT_GROQ_MODEL
    )
    timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("GROQ_TIMEOUT_SECONDS", "10"))
    )
    temperature: float = 0.2
    max_tokens: Optional[int] = 1024


class GroqClient:
    """Cliente que cumple la interfaz LLMClient apuntando a la API de Groq."""

    def __init__(self, config: Optional[GroqClientConfig] = None) -> None:
        if OpenAI is None:
            raise RuntimeError(
                "El paquete 'openai' es requerido para GroqClient. "
                "Instálalo con: pip install openai>=1.0.0"
            )

        self.config = config or GroqClientConfig()

        if not self.config.api_key:
            logger.warning(
                "GROQ_API_KEY no configurada — GroqClient fallará con ValueError "
                "al generar y ExplanationService conmutará al siguiente proveedor."
            )

        # En producción el transporte debe ser HTTPS (misma política que OllamaClient).
        if (
            os.getenv("ENVIRONMENT", "dev").lower() == "prod"
            and not self.config.base_url.lower().startswith("https://")
        ):
            raise RuntimeError(
                "GROQ_BASE_URL debe usar HTTPS en producción para proteger la API key."
            )

        self._client = OpenAI(
            api_key=self.config.api_key or "missing_groq_key",
            base_url=self.config.base_url,
            timeout=float(self.config.timeout_seconds),
        )
        logger.info(
            "GroqClient inicializado → base_url=%s, model=%s, timeout=%.1fs",
            self.config.base_url,
            self.config.model,
            self.config.timeout_seconds,
        )

    def generate(self, prompt: str, *, model: Optional[str] = None) -> str:
        """Envía el prompt a Groq y devuelve el texto JSON de la explicación.

        Raises:
            ValueError: si no hay API key (ExplanationService lo trata como
                proveedor no disponible y hace fallover).
            RateLimitError: cuota/RPM excedida — fallover inmediato sin retry.
            APIConnectionError / APITimeoutError: red o timeout — fallover.
            RuntimeError: respuesta vacía del modelo.
        """
        target_model = (model or self.config.model).strip()

        if not self.config.api_key:
            raise ValueError("GROQ_API_KEY es requerida para explicar con Groq.")

        messages = [
            {
                "role": "system",
                "content": (
                    "Eres el motor de análisis forense de malware de ShadowNet Defender. "
                    "Explicas resultados ya calculados; NO detectas malware. "
                    "Responde ÚNICAMENTE con JSON válido según las instrucciones."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        try:
            response = self._client.chat.completions.create(
                model=target_model,
                messages=messages,  # type: ignore[arg-type]
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                response_format={"type": "json_object"},
            )
        except RateLimitError as exc:
            # 429: propagar sin envolver — el servicio debe saltar de proveedor ya.
            logger.warning("Groq rate limit (HTTP 429): %s", exc)
            raise
        except APITimeoutError as exc:
            logger.warning("Groq timeout (%.1fs): %s", self.config.timeout_seconds, exc)
            raise
        except APIConnectionError as exc:
            logger.warning("Groq error de conexión: %s", exc)
            raise
        except APIError as exc:
            logger.error("Groq APIError status=%s: %s", getattr(exc, "status_code", "?"), exc)
            raise

        content = (response.choices[0].message.content or "").strip()
        if not content:
            raise RuntimeError("Groq devolvió una respuesta vacía.")
        return content
