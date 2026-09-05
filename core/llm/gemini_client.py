"""
core/llm/gemini_client.py — Cliente Google Gemini vía endpoint OpenAI-compatible.

Provider secundario de la cascada Tri-Fallover (groq -> gemini -> template).
Hereda de BaseLLMClient; añade estrategia de capacidad: ante 503 del modelo
pedido, reintenta contra GEMINI_FALLBACK_MODEL antes de devolver el error a
la cascada. Incluye variante async para futuros callers non-blocking.
Google AI Studio expone https://generativelanguage.googleapis.com/v1beta/openai/
compatible con el SDK `openai`, por lo que no se añade google-generativeai
al stack de producción.

Modelo por defecto: gemini-3.5-flash-lite. La clave GEMINI_API_KEY se genera
en https://aistudio.google.com/apikey y se resuelve desde el entorno.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from .base_client import BaseLLMClient, LLMClientConfig

try:
    from openai import (
        APIConnectionError,
        APIError,
        APITimeoutError,
        AsyncOpenAI,
        RateLimitError,
    )
except ImportError:  # pragma: no cover
    AsyncOpenAI = None  # type: ignore[assignment]
    APIConnectionError = APIError = APITimeoutError = RateLimitError = Exception  # type: ignore[assignment,misc]

logger = logging.getLogger("shadownet.llm.gemini")

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"
# Modelo estable de respaldo: gemini-3.5-flash-lite sufre 503 intermitentes
# por alta demanda global (verificado 2026-09-04). gemini-3.1-flash-lite
# responde en ~3s con JSON válido y degrada dentro del proveedor.
GEMINI_FALLBACK_MODEL = "gemini-3.1-flash-lite"


@dataclass
class GeminiClientConfig(LLMClientConfig):
    """Configuración del cliente Gemini (sobrescribible por env y por tests)."""

    api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    base_url: str = GEMINI_BASE_URL
    model: str = field(default_factory=lambda: os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL)
    timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("GEMINI_TIMEOUT_SECONDS", "12"))
    )
    temperature: float = 0.2
    max_tokens: Optional[int] = 1024


class GeminiClient(BaseLLMClient):
    """Cliente síncrono para Gemini con degradación interna ante 503."""

    def __init__(self, config: Optional[GeminiClientConfig] = None) -> None:
        resolved = config or GeminiClientConfig()
        # BaseLLMClient inicializa OpenAI, valida HTTPS y loguea; reutilizamos.
        super().__init__(resolved, provider_name="Gemini", api_key_env="GEMINI_API_KEY")

    def generate(self, prompt: str, *, model: Optional[str] = None) -> str:
        """Envía el prompt a Gemini y devuelve el JSON de la explicación.

        Estrategia de capacidad: intenta `model` (o el configurado); si Google
        responde 503 por saturación del modelo, reintenta UNA vez contra
        GEMINI_FALLBACK_MODEL. Eso degrada dentro del propio proveedor en vez
        de gastar un salto completo de la cascada Tri-Fallover.
        """
        target_model = (model or self.config.model).strip()

        if not self.config.api_key:
            raise ValueError("GEMINI_API_KEY es requerida para explicar con Gemini.")

        messages = self._build_messages(prompt)

        attempt_models = [target_model]
        if target_model != GEMINI_FALLBACK_MODEL:
            attempt_models.append(GEMINI_FALLBACK_MODEL)

        last_error: Optional[BaseException] = None
        for candidate in attempt_models:
            try:
                response = self._client.chat.completions.create(
                    model=candidate,
                    messages=messages,  # type: ignore[arg-type]
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    response_format={"type": "json_object"},
                )
            except RateLimitError as exc:
                self._logger.warning("Gemini rate limit / cuota excedida (HTTP 429): %s", exc)
                raise
            except APITimeoutError as exc:
                self._logger.warning(
                    "Gemini timeout (%.1fs): %s", float(self.config.timeout_seconds), exc
                )
                raise
            except APIConnectionError as exc:
                self._logger.warning("Gemini error de conexion: %s", exc)
                raise
            except APIError as exc:
                status = getattr(exc, "status_code", None)
                if status == 503 and candidate != attempt_models[-1]:
                    self._logger.warning(
                        "Gemini %s saturado (503); reintentando con %s",
                        candidate,
                        attempt_models[-1],
                    )
                    last_error = exc
                    continue
                self._logger.error("Gemini APIError status=%s: %s", status, exc)
                raise
            else:
                content = self._extract_content(response)
                if candidate != target_model:
                    self._logger.info("Gemini servido por modelo degradado %s", candidate)
                return content

        raise RuntimeError(f"Gemini no disponible tras reintentos: {last_error}")


class AsyncGeminiClient:
    """Variante async del proveedor secundario para callers non-blocking."""

    def __init__(self, config: Optional[GeminiClientConfig] = None) -> None:
        if AsyncOpenAI is None:  # pragma: no cover
            raise RuntimeError("El paquete 'openai>=1.0.0' es requerido para AsyncGeminiClient.")
        self.config = config or GeminiClientConfig()
        self._client = AsyncOpenAI(
            api_key=self.config.api_key or "missing_gemini_key",
            base_url=self.config.base_url,
            timeout=float(self.config.timeout_seconds),
        )

    async def generate(self, prompt: str, *, model: Optional[str] = None) -> str:
        """Versión non-blocking de GeminiClient.generate — mismos errores propagados."""
        target_model = (model or self.config.model).strip()
        if not self.config.api_key:
            raise ValueError("GEMINI_API_KEY es requerida para explicar con Gemini.")

        response = await self._client.chat.completions.create(
            model=target_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Eres el motor de analisis forense de malware de ShadowNet Defender. "
                        "Responde UNICAMENTE con JSON valido segun las instrucciones."
                    ),
                },
                {"role": "user", "content": prompt},
            ],  # type: ignore[arg-type]
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            response_format={"type": "json_object"},
        )
        return (response.choices[0].message.content or "").strip()
