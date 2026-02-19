from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, Optional, Protocol

from .ollama_client import OllamaClient, OllamaClientConfig
from .prompt_builder import build_llm_prompt

logger = logging.getLogger("shadownet.llm.service")


class LLMClient(Protocol):
    """
    Contrato mínimo para clientes LLM.

    Permite reemplazar Ollama por OpenAI, Gemini o Claude sin cambiar la capa de servicio.
    """

    def generate(self, prompt: str, *, model: str | None = None) -> str:
        ...


@dataclass
class ExplanationServiceConfig:
    """
    Configuración del servicio de explicación.

    Lee OLLAMA_MODEL del entorno para determinar el modelo por defecto.
    """

    default_provider: str = "ollama"
    default_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    )


class ExplanationService:
    """
    Servicio de alto nivel que genera explicación de resultados ML.

    Usa OllamaClient (OpenAI SDK) para comunicarse con Ollama,
    ya sea local o remoto vía Cloudflare Tunnel.
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
        Genera explicación basada en el JSON de escaneo.
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
        return {
            "provider": resolved_provider,
            "model": resolved_model,
            "response_text": response_text,
            "prompt_version": "v1",
        }
