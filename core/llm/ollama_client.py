from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict
from urllib import error, request


@dataclass
class OllamaClientConfig:
    """
    Configuración del cliente de Ollama.
    """

    base_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    model: str = os.getenv("OLLAMA_MODEL", "mistral")
    timeout_seconds: int = 60


class OllamaClient:
    """
    Cliente HTTP mínimo para Ollama (/api/generate).
    """

    def __init__(self, config: OllamaClientConfig | None = None):
        self.config = config or OllamaClientConfig()

    def generate(self, prompt: str, *, model: str | None = None) -> str:
        """
        Envía un prompt a Ollama y devuelve texto generado.
        """
        resolved_model = model or self.config.model
        url = f"{self.config.base_url.rstrip('/')}/api/generate"
        payload = {
            "model": resolved_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }

        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8")
                data: Dict[str, Any] = json.loads(raw) if raw else {}
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise RuntimeError(
                "No se pudo conectar a Ollama. Verifica que esté activo en "
                f"{self.config.base_url} ({exc})"
            ) from exc

        if "response" not in data:
            raise RuntimeError(f"Respuesta inesperada de Ollama: {data}")
        return str(data["response"]).strip()

