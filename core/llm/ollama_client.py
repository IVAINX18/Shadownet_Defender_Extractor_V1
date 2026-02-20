"""
core/llm/ollama_client.py — Cliente Ollama usando OpenAI SDK (compatible con Cloudflare Tunnel)

=============================================================================
ARQUITECTURA:
  Ollama expone una API compatible con OpenAI en /v1.
  Usamos el SDK oficial de OpenAI para comunicarnos con Ollama, ya sea:
    - Localmente: http://localhost:11434/v1
    - Remotamente vía Cloudflare Tunnel: https://xxxx.trycloudflare.com/v1

  Esto permite que el backend en Render (nube) consuma Ollama corriendo
  en la máquina del desarrollador a través de un túnel seguro HTTPS.

VARIABLES DE ENTORNO:
  OLLAMA_BASE_URL  — URL base de Ollama (REQUERIDA en producción)
                     Ejemplo local:  http://localhost:11434/v1
                     Ejemplo remoto: https://xxxx.trycloudflare.com/v1
  OLLAMA_MODEL     — Modelo a usar (default: llama3.2:3b)

NOTA PARA ESTUDIANTES:
  - Ollama ignora el api_key, pero el SDK de OpenAI lo requiere.
    Usamos "ollama" como valor dummy.
  - El timeout es alto (120s) porque modelos grandes pueden tardar
    en generar la primera respuesta (especialmente en CPU).
=============================================================================
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Importar OpenAI SDK (pip install openai)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from openai import OpenAI, APIConnectionError, APITimeoutError, APIStatusError
except ImportError as exc:
    raise ImportError(
        "El paquete 'openai' es requerido para el cliente Ollama.\n"
        "Instálalo con: pip install openai\n"
        "O agrega 'openai>=1.0.0' a requirements.txt"
    ) from exc

# ─────────────────────────────────────────────────────────────────────────────
# Logger del módulo
# ─────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("shadownet.llm.ollama")


def _normalize_ollama_base_url(value: str | None) -> str:
    """
    Normalizes OLLAMA_BASE_URL values coming from env or dashboard copy/paste.

    Accepts malformed inputs such as:
    - "OLLAMA_BASE_URL=https://xxxx.trycloudflare.com/v1"
    - "export OLLAMA_BASE_URL=https://xxxx.trycloudflare.com/v1"
    - quoted values
    """
    default_url = "http://127.0.0.1:11434/v1"
    text = str(value or "").strip().strip("'").strip('"')
    if not text:
        return default_url

    lower_text = text.lower()
    key_tokens = ("ollama_base_url=", "export ollama_base_url=")
    for token in key_tokens:
        idx = lower_text.find(token)
        if idx != -1:
            text = text[idx + len(token) :].strip()
            break

    if text.startswith("="):
        text = text[1:].strip()

    return text or default_url


@dataclass
class OllamaClientConfig:
    """
    Configuración del cliente de Ollama.

    Atributos:
        base_url         — URL base del endpoint OpenAI-compatible de Ollama.
                           En local: http://localhost:11434/v1
                           En remoto (Cloudflare Tunnel): https://xxxx.trycloudflare.com/v1
        model            — Nombre del modelo en Ollama (ej: llama3.2:3b, phi3:mini, mistral).
        timeout_seconds  — Timeout máximo para la petición HTTP (en segundos).
        temperature      — Temperatura de generación (0.0 = determinista, 1.0 = creativo).
        max_tokens       — Máximo de tokens a generar (None = sin límite explícito).
    """

    base_url: str = field(
        default_factory=lambda: _normalize_ollama_base_url(os.getenv("OLLAMA_BASE_URL"))
    )
    model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    )
    timeout_seconds: int = 120
    temperature: float = 0.7
    max_tokens: Optional[int] = None

    def __post_init__(self) -> None:
        self.base_url = _normalize_ollama_base_url(self.base_url)


class OllamaClient:
    """
    Cliente para Ollama usando el SDK de OpenAI (API compatible /v1).

    Funciona tanto con Ollama local como con Ollama expuesto vía
    Cloudflare Tunnel (URL pública HTTPS).

    Ejemplo de uso:
        >>> client = OllamaClient()
        >>> response = client.generate("Explica qué es un ransomware.")
        >>> print(response)
    """

    def __init__(self, config: OllamaClientConfig | None = None):
        self.config = config or OllamaClientConfig()

        # ─────────────────────────────────────────────────────────────────────
        # Validar que OLLAMA_BASE_URL esté configurada en producción
        # ─────────────────────────────────────────────────────────────────────
        env = os.getenv("ENVIRONMENT", "dev")
        if env == "prod" and "127.0.0.1" in self.config.base_url:
            raise RuntimeError(
                "⚠️  OLLAMA_BASE_URL apunta a localhost pero ENVIRONMENT=prod.\n"
                "En producción (Render), Ollama no está disponible localmente.\n"
                "Configura OLLAMA_BASE_URL con la URL de tu Cloudflare Tunnel:\n"
                "  Ejemplo: https://xxxx.trycloudflare.com/v1\n"
                "  Ver: docs/cloudflare-tunnel-setup.md"
            )

        # ─────────────────────────────────────────────────────────────────────
        # Crear cliente OpenAI apuntando a Ollama
        # api_key="ollama" es un valor dummy — Ollama no requiere autenticación
        # ─────────────────────────────────────────────────────────────────────
        self._client = OpenAI(
            base_url=self.config.base_url,
            api_key="ollama",
            timeout=float(self.config.timeout_seconds),
        )

        logger.info(
            "OllamaClient inicializado → base_url=%s, model=%s, timeout=%ds",
            self.config.base_url,
            self.config.model,
            self.config.timeout_seconds,
        )

    def generate(self, prompt: str, *, model: str | None = None) -> str:
        """
        Envía un prompt a Ollama y devuelve el texto generado.

        Usa el endpoint /v1/chat/completions (formato OpenAI) internamente.

        Args:
            prompt: Texto del prompt a enviar.
            model:  Modelo a usar (sobreescribe el default de config).

        Returns:
            Texto generado por el modelo.

        Raises:
            RuntimeError: Si hay error de conexión, timeout o respuesta inesperada.
        """
        resolved_model = model or self.config.model

        # ─────────────────────────────────────────────────────────────────────
        # Construir mensajes en formato chat (OpenAI-compatible)
        # ─────────────────────────────────────────────────────────────────────
        messages: List[Dict[str, str]] = [
            {
                "role": "system",
                "content": (
                    "Eres un analista de ciberseguridad experto. "
                    "Responde de forma técnica, precisa y estructurada."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        logger.info(
            "Enviando petición a Ollama → model=%s, prompt_length=%d chars",
            resolved_model,
            len(prompt),
        )

        try:
            # ─────────────────────────────────────────────────────────────────
            # Llamada al endpoint /v1/chat/completions de Ollama
            # ─────────────────────────────────────────────────────────────────
            response = self._client.chat.completions.create(
                model=resolved_model,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stream=False,
            )

            # ─────────────────────────────────────────────────────────────────
            # Extraer contenido de la respuesta
            # ─────────────────────────────────────────────────────────────────
            content = response.choices[0].message.content
            if content is None:
                raise RuntimeError("Ollama devolvió una respuesta vacía (content=None).")

            logger.info(
                "Respuesta recibida de Ollama → model=%s, response_length=%d chars, "
                "usage=%s",
                resolved_model,
                len(content),
                getattr(response, "usage", "N/A"),
            )

            return content.strip()

        except APITimeoutError as exc:
            # IMPORTANTE: APITimeoutError hereda de APIConnectionError,
            # por eso debe ir ANTES en la cadena de except.
            logger.error(
                "Timeout al esperar respuesta de Ollama (timeout=%ds): %s",
                self.config.timeout_seconds,
                exc,
            )
            raise RuntimeError(
                f"Ollama no respondió en {self.config.timeout_seconds} segundos.\n"
                f"Posibles causas:\n"
                f"  - El modelo es muy grande para tu hardware\n"
                f"  - Ollama está cargando el modelo por primera vez\n"
                f"  - Prueba con un modelo más ligero: phi3:mini o llama3.2:1b\n"
                f"Error: {exc}"
            ) from exc

        except APIConnectionError as exc:
            logger.error("Error de conexión con Ollama: %s", exc)
            raise RuntimeError(
                f"No se pudo conectar a Ollama en {self.config.base_url}.\n"
                f"Verifica que:\n"
                f"  1. Ollama esté corriendo (ollama serve)\n"
                f"  2. Cloudflare Tunnel esté activo (si usas URL remota)\n"
                f"  3. La URL sea correcta: {self.config.base_url}\n"
                f"Error: {exc}"
            ) from exc

        except APIStatusError as exc:
            logger.error(
                "Error HTTP de Ollama (status=%s): %s",
                exc.status_code,
                exc.message,
            )
            raise RuntimeError(
                f"Ollama respondió con error HTTP {exc.status_code}.\n"
                f"Mensaje: {exc.message}\n"
                f"Verifica que el modelo '{resolved_model}' esté descargado:\n"
                f"  ollama pull {resolved_model}"
            ) from exc

        except Exception as exc:
            logger.error("Error inesperado al comunicarse con Ollama: %s", exc)
            raise RuntimeError(
                f"Error inesperado al comunicarse con Ollama: {exc}"
            ) from exc
