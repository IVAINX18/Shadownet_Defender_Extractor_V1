"""
Capa LLM de ShadowNet Defender.

Este paquete encapsula:
- Construcción de prompts seguros para explicación.
- Cliente HTTP para Ollama.
- Servicio de explicación desacoplado del resto del sistema.
"""

from .prompt_builder import build_llm_prompt, extract_scan_summary
from .ollama_client import OllamaClient, OllamaClientConfig
from .explanation_service import ExplanationService, ExplanationServiceConfig

__all__ = [
    "build_llm_prompt",
    "extract_scan_summary",
    "OllamaClient",
    "OllamaClientConfig",
    "ExplanationService",
    "ExplanationServiceConfig",
]

