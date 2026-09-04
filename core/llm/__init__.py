"""
Capa LLM de ShadowNet Defender.

Este paquete encapsula:
- Construcción de prompts seguros para explicación.
- Clientes HTTP para los proveedores de la cascada Tri-Fallover:
  Groq (primario cloud), Gemini (secundario cloud), Ollama (local avanzado)
  y TemplateExplainer (fallback offline determinístico sin IA).
- Servicio de explicación desacoplado del resto del sistema.
"""

from .prompt_builder import build_llm_prompt, extract_scan_summary
from .ollama_client import OllamaClient, OllamaClientConfig
from .groq_client import GroqClient, GroqClientConfig
from .gemini_client import AsyncGeminiClient, GeminiClient, GeminiClientConfig
from .template_explainer import TemplateExplainer
from .explanation_service import ExplanationService, ExplanationServiceConfig

__all__ = [
    "build_llm_prompt",
    "extract_scan_summary",
    "OllamaClient",
    "OllamaClientConfig",
    "GroqClient",
    "GroqClientConfig",
    "GeminiClient",
    "GeminiClientConfig",
    "AsyncGeminiClient",
    "TemplateExplainer",
    "ExplanationService",
    "ExplanationServiceConfig",
]
