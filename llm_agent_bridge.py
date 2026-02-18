from __future__ import annotations

"""
Compatibilidad retroactiva.

Este módulo mantiene la interfaz previa `LLMAgentBridge` para no romper código existente,
delegando internamente en la nueva capa limpia `core.llm`.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from core.llm.explanation_service import ExplanationService, ExplanationServiceConfig


@dataclass
class LLMBridgeConfig:
    """
    Config de compatibilidad. Se preserva por backward compatibility.
    """

    ollama_model: str = "mistral"


class LLMAgentBridge:
    """
    Adaptador que mantiene el contrato antiguo del bridge.
    """

    def __init__(self, config: Optional[LLMBridgeConfig] = None):
        cfg = config or LLMBridgeConfig()
        self.service = ExplanationService(
            config=ExplanationServiceConfig(
                default_provider="ollama",
                default_model=cfg.ollama_model,
            )
        )

    @staticmethod
    def build_prompt(scan_result: Dict[str, Any]) -> str:
        from core.llm.prompt_builder import build_llm_prompt

        return build_llm_prompt(scan_result)

    def explain_scan(
        self,
        scan_result: Dict[str, Any],
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        # Por requerimiento actual solo se habilita Ollama en producción local.
        if provider and provider.strip().lower() != "ollama":
            raise ValueError("Proveedor no soportado en esta fase. Use provider='ollama'.")
        return self.service.explain(scan_result, provider="ollama", model=model)

