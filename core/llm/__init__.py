"""
Capa LLM de ShadowNet Defender — solo nube.

Este paquete encapsula:
- Construccion de prompts seguros para explicacion.
- Clientes HTTP para la cascada Tri-Fallover cloud:
  Groq (primario), Gemini (secundario) y TemplateExplainer
  (fallback offline deterministico sin IA ni red).
- Servicio de explicacion desacoplado del resto del sistema.

BaseLLMClient concentra el esqueleto OpenAI-compatible compartido
entre proveedores cloud.
"""

from .base_client import BaseLLMClient, LLMClientConfig
from .prompt_builder import build_llm_prompt, extract_scan_summary
from .groq_client import GroqClient, GroqClientConfig
from .gemini_client import AsyncGeminiClient, GeminiClient, GeminiClientConfig
from .template_explainer import TemplateExplainer
from .explanation_service import ExplanationService, ExplanationServiceConfig

__all__ = [
    "BaseLLMClient",
    "LLMClientConfig",
    "build_llm_prompt",
    "extract_scan_summary",
    "GroqClient",
    "GroqClientConfig",
    "GeminiClient",
    "GeminiClientConfig",
    "AsyncGeminiClient",
    "TemplateExplainer",
    "ExplanationService",
    "ExplanationServiceConfig",
]
