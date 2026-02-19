from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict
from urllib import error, request

from utils.logger import setup_logger

logger = setup_logger(__name__)


def _to_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class N8NClientConfig:
    webhook_url: str = os.getenv("N8N_WEBHOOK_URL", "")
    enabled: bool = _to_bool(os.getenv("N8N_ENABLED", "false"))
    timeout_seconds: int = int(os.getenv("N8N_TIMEOUT_SECONDS", "8"))


class N8NClient:
    """
    Cliente desacoplado para automatización externa con n8n.

    Diseño no bloqueante:
    - Si está deshabilitado o falta URL, omite envío.
    - Si falla la red o el endpoint, registra error y no rompe el flujo principal.
    """

    def __init__(self, config: N8NClientConfig | None = None):
        self.config = config or N8NClientConfig()

    def is_enabled(self) -> bool:
        return self.config.enabled and bool(self.config.webhook_url.strip())

    def send_analysis_event(self, payload: Dict[str, Any]) -> bool:
        if not self.config.enabled:
            logger.debug("N8N disabled. Skipping automation event.")
            return False
        if not self.config.webhook_url.strip():
            logger.warning("N8N enabled but N8N_WEBHOOK_URL is empty. Skipping event.")
            return False

        req = request.Request(
            self.config.webhook_url.strip(),
            data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                status = getattr(resp, "status", 200)
                if status >= 400:
                    logger.warning("n8n responded with status %s", status)
                    return False
            logger.info("n8n automation event delivered.")
            return True
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            logger.warning("n8n HTTP error %s: %s", exc.code, detail)
        except error.URLError as exc:
            logger.warning("n8n connection error: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Unexpected n8n automation error: %s", exc)
        return False
