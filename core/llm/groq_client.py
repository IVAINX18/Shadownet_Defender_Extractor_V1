"""
core/llm/groq_client.py — Cliente Groq API vía endpoint OpenAI-compatible.

Provider primario de la cascada Tri-Fallover (groq -> gemini -> template).
Hereda de BaseLLMClient para compartir validación, creación de cliente OpenAI
y flujo generate() — solo aporta defaults de entorno y constantes propias.
Modelo por defecto: openai/gpt-oss-20b, validado 2026-09-01 contra
GET /openai/v1/models para esta organización. No reintroducir Llama 3.1/3.3
(no habilitados para esta API key).

Contrato de errores: RateLimitError y fallos de red/timeout se propagan sin
envolver para que ExplanationService decida el fallover.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from .base_client import BaseLLMClient, LLMClientConfig

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"


@dataclass
class GroqClientConfig(LLMClientConfig):
    """Configuración del cliente Groq (100% sobrescribible para tests)."""

    api_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", ""))
    base_url: str = GROQ_BASE_URL
    model: str = field(default_factory=lambda: os.getenv("GROQ_MODEL") or DEFAULT_GROQ_MODEL)
    timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("GROQ_TIMEOUT_SECONDS", "10"))
    )
    temperature: float = 0.2
    max_tokens: Optional[int] = 1024


class GroqClient(BaseLLMClient):
    """Cliente que cumple la interfaz LLMClient apuntando a la API de Groq."""

    def __init__(self, config: Optional[GroqClientConfig] = None) -> None:
        resolved = config or GroqClientConfig()
        super().__init__(resolved, provider_name="Groq", api_key_env="GROQ_API_KEY")
