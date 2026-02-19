"""
llm_agent_bridge.py — Puente LLM para ShadowNet Defender (Ollama vía Cloudflare Tunnel)

=============================================================================
PROPÓSITO:
  Este módulo es el adaptador principal que conecta el pipeline de análisis
  de malware con el LLM (Ollama). Mantiene compatibilidad retroactiva con
  el código existente mientras usa internamente el SDK de OpenAI para
  comunicarse con Ollama (local o remoto vía Cloudflare Tunnel).

FLUJO:
  1. El usuario/API solicita una explicación de un scan_result.
  2. LLMAgentBridge construye un prompt seguro (prompt_builder.py).
  3. Envía el prompt a Ollama vía OpenAI SDK (ollama_client.py).
  4. Ollama puede estar:
     - Local: http://localhost:11434/v1
     - Remoto: https://xxxx.trycloudflare.com/v1 (Cloudflare Tunnel)
  5. Retorna la explicación estructurada.

VARIABLES DE ENTORNO:
  OLLAMA_BASE_URL  — URL del endpoint OpenAI-compatible de Ollama (REQUERIDA en prod)
  OLLAMA_MODEL     — Modelo a usar (default: llama3.2:3b)

EJEMPLO DE USO:
  >>> bridge = LLMAgentBridge()
  >>> result = bridge.explain_scan(scan_result)
  >>> print(result["response_text"])

NOTA PARA ESTUDIANTES:
  Este archivo existe por compatibilidad retroactiva. La lógica real está en:
  - core/llm/ollama_client.py   → Cliente HTTP (OpenAI SDK)
  - core/llm/prompt_builder.py  → Construcción segura de prompts
  - core/llm/explanation_service.py → Servicio de explicación desacoplado
=============================================================================
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from core.llm.explanation_service import ExplanationService, ExplanationServiceConfig

# ─────────────────────────────────────────────────────────────────────────────
# Logger del módulo
# ─────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("shadownet.llm.bridge")


@dataclass
class LLMBridgeConfig:
    """
    Configuración del bridge LLM.

    Lee las variables de entorno para determinar el modelo a usar.
    En producción (Render), OLLAMA_BASE_URL debe apuntar al Cloudflare Tunnel.

    Atributos:
        ollama_model — Nombre del modelo en Ollama.
                       Se lee de OLLAMA_MODEL o usa "llama3.2:3b" por defecto.
    """

    ollama_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    )


class LLMAgentBridge:
    """
    Adaptador principal para explicaciones LLM en ShadowNet Defender.

    Mantiene el contrato antiguo del bridge para no romper código existente
    (api_server.py, cli.py, tests), delegando internamente en la capa limpia
    core.llm que usa OpenAI SDK para comunicarse con Ollama.

    Ejemplo:
        >>> bridge = LLMAgentBridge()
        >>> scan = {"label": "Malware", "score": 0.95, "confidence": "High"}
        >>> result = bridge.explain_scan(scan)
        >>> print(result["response_text"])
    """

    def __init__(self, config: Optional[LLMBridgeConfig] = None):
        cfg = config or LLMBridgeConfig()

        # ─────────────────────────────────────────────────────────────────────
        # Log de configuración para debugging
        # ─────────────────────────────────────────────────────────────────────
        ollama_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1")
        logger.info(
            "LLMAgentBridge inicializado → model=%s, base_url=%s",
            cfg.ollama_model,
            ollama_url,
        )

        # ─────────────────────────────────────────────────────────────────────
        # Crear el servicio de explicación con el proveedor Ollama
        # ExplanationService internamente crea un OllamaClient que usa
        # OpenAI SDK apuntando a OLLAMA_BASE_URL
        # ─────────────────────────────────────────────────────────────────────
        self.service = ExplanationService(
            config=ExplanationServiceConfig(
                default_provider="ollama",
                default_model=cfg.ollama_model,
            )
        )

    @staticmethod
    def build_prompt(scan_result: Dict[str, Any]) -> str:
        """
        Construye un prompt seguro a partir del resultado de escaneo.

        Delega en core.llm.prompt_builder para mantener la lógica centralizada.

        Args:
            scan_result: Diccionario con el resultado del escaneo ML.

        Returns:
            String con el prompt formateado para el LLM.
        """
        from core.llm.prompt_builder import build_llm_prompt

        return build_llm_prompt(scan_result)

    def explain_scan(
        self,
        scan_result: Dict[str, Any],
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Genera una explicación LLM del resultado de escaneo.

        Args:
            scan_result: Diccionario con el resultado del escaneo ML.
            provider:    Proveedor LLM a usar (default: "ollama").
            model:       Modelo específico (sobreescribe el default).

        Returns:
            Diccionario con:
              - provider: str — Proveedor usado (ej: "ollama")
              - model: str — Modelo usado (ej: "llama3.2:3b")
              - response_text: str — Explicación generada por el LLM
              - prompt_version: str — Versión del prompt usado

        Raises:
            RuntimeError: Si Ollama no está disponible o hay error de conexión.
            ValueError: Si el proveedor no está registrado.
        """
        logger.info(
            "explain_scan llamado → provider=%s, model=%s, label=%s, score=%s",
            provider or "ollama",
            model or "default",
            scan_result.get("label", "?"),
            scan_result.get("score", "?"),
        )

        result = self.service.explain(scan_result, provider=provider, model=model)

        logger.info(
            "Explicación generada → provider=%s, model=%s, response_length=%d chars",
            result.get("provider"),
            result.get("model"),
            len(result.get("response_text", "")),
        )

        return result
