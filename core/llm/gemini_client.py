"""
core/llm/gemini_client.py — Cliente Google Gemini vía endpoint OpenAI-compatible.

Provider secundario de la cascada Tri-Fallover (groq -> gemini -> template).
Se usa cuando Groq agota su free tier (30 RPM / 1K RPD) o falla por red.

Google AI Studio expone https://generativelanguage.googleapis.com/v1beta/openai/
compatible con el SDK `openai`, así que NO se añade google-generativeai al
stack de producción (menos dependencias = menor superficie de supply chain).

Modelo por defecto: gemini-3.5-flash-lite (gemini-2.0-flash-lite fue retirado).
La clave GEMINI_API_KEY se genera en https://aistudio.google.com/apikey y se
resuelve desde el entorno — nunca se hardcodea ni se loguea.

Contrato de errores: RateLimitError y fallos de red/timeout se propagan sin
envolver para que ExplanationService conmute al TemplateExplainer.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

try:
    from openai import (
        AsyncOpenAI,
        OpenAI,
        APIConnectionError,
        APIError,
        APITimeoutError,
        RateLimitError,
    )
except ImportError:
    OpenAI = AsyncOpenAI = None  # type: ignore[assignment]
    APIConnectionError = APIError = APITimeoutError = RateLimitError = Exception  # type: ignore[assignment,misc]

logger = logging.getLogger("shadownet.llm.gemini")

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"
# Modelo estable de respaldo: gemini-3.5-flash-lite está en alta demanda
# global (503 intermitentes verificados 2026-09-04). gemini-3.1-flash-lite
# responde en ~3s con JSON válido y sirve de degradación controlada DENTRO
# del proveedor, antes de que ExplanationService conmute a template.
GEMINI_FALLBACK_MODEL = "gemini-3.1-flash-lite"


@dataclass
class GeminiClientConfig:
    """Configuración del cliente Gemini (sobrescribible por env y por tests)."""

    api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    base_url: str = GEMINI_BASE_URL
    model: str = field(
        default_factory=lambda: os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
    )
    timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("GEMINI_TIMEOUT_SECONDS", "12"))
    )
    temperature: float = 0.2
    max_tokens: Optional[int] = 1024


class GeminiClient:
    """Cliente síncrono que cumple la interfaz LLMClient para Gemini."""

    def __init__(self, config: Optional[GeminiClientConfig] = None) -> None:
        if OpenAI is None:
            raise RuntimeError(
                "El paquete 'openai' es requerido para GeminiClient. "
                "Instálalo con: pip install openai>=1.0.0"
            )

        self.config = config or GeminiClientConfig()

        if not self.config.api_key:
            logger.warning(
                "GEMINI_API_KEY no configurada — GeminiClient fallará con ValueError "
                "al generar y ExplanationService conmutará a TemplateExplainer."
            )

        # Política de transporte idéntica a GroqClient/OllamaClient: HTTPS en prod.
        if (
            os.getenv("ENVIRONMENT", "dev").lower() == "prod"
            and not self.config.base_url.lower().startswith("https://")
        ):
            raise RuntimeError(
                "GEMINI_BASE_URL debe usar HTTPS en producción para proteger la API key."
            )

        self._client = OpenAI(
            api_key=self.config.api_key or "missing_gemini_key",
            base_url=self.config.base_url,
            timeout=float(self.config.timeout_seconds),
        )
        logger.info(
            "GeminiClient inicializado → base_url=%s, model=%s, timeout=%.1fs",
            self.config.base_url,
            self.config.model,
            self.config.timeout_seconds,
        )

    def generate(self, prompt: str, *, model: Optional[str] = None) -> str:
        """Envía el prompt a Gemini y devuelve el JSON de la explicación forense.

        Estrategia de capacidad: intenta `model` (o el configured); si Google
        responde 503/429 por saturación del modelo, reintenta UNA vez contra
        GEMINI_FALLBACK_MODEL. Eso degrada dentro del propio proveedor en vez
        de gastar un salto completo de la cascada Tri-Fallover.

        Raises:
            ValueError: sin API key — proveedor no disponible, fallover.
            RateLimitError: 429/cuota diaria de AI Studio — fallover inmediato.
            APIConnectionError / APITimeoutError: red o timeout — fallover.
            RuntimeError: respuesta vacía del modelo.
        """
        target_model = (model or self.config.model).strip()

        if not self.config.api_key:
            raise ValueError("GEMINI_API_KEY es requerida para explicar con Gemini.")

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

        # Primer intento en el modelo pedido; reintento local solo si hay 503.
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
                logger.warning("Gemini rate limit / cuota excedida (HTTP 429): %s", exc)
                raise
            except APITimeoutError as exc:
                logger.warning("Gemini timeout (%.1fs): %s", self.config.timeout_seconds, exc)
                raise
            except APIConnectionError as exc:
                logger.warning("Gemini error de conexión: %s", exc)
                raise
            except APIError as exc:
                status = getattr(exc, "status_code", None)
                # 503 = capacidad del modelo: degrada al fallback en vez de fallar.
                if status == 503 and candidate != attempt_models[-1]:
                    logger.warning(
                        "Gemini %s saturado (503); reintentando con %s",
                        candidate, attempt_models[-1],
                    )
                    last_error = exc
                    continue
                logger.error("Gemini APIError status=%s: %s", status, exc)
                raise
            else:
                content = (response.choices[0].message.content or "").strip()
                if not content:
                    raise RuntimeError("Gemini devolvió una respuesta vacía.")
                if candidate != target_model:
                    logger.info("Gemini servido por modelo degradado %s", candidate)
                return content

        # Agotados los intentos sin excepción lanzada (defensivo).
        raise RuntimeError(f"Gemini no disponible tras reintentos: {last_error}")


class AsyncGeminiClient:
    """Variante async del proveedor secundario.

    Para llamadores que ya operan en un event loop (FastAPI async routes o el
    proceso Electron sin bloquear la UI). ExplanationService usa la variante
    síncrona porque su contrato LLMClient es blocking; esta clase se expone
    para la fase de conversión async del backend.
    """

    def __init__(self, config: Optional[GeminiClientConfig] = None) -> None:
        if AsyncOpenAI is None:
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
                        "Eres el motor de análisis forense de malware de ShadowNet Defender. "
                        "Responde ÚNICAMENTE con JSON válido según las instrucciones."
                    ),
                },
                {"role": "user", "content": prompt},
            ],  # type: ignore[arg-type]
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            response_format={"type": "json_object"},
        )
        return (response.choices[0].message.content or "").strip()
