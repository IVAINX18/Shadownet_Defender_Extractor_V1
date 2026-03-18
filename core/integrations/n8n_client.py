"""
core/integrations/n8n_client.py — Integración con N8N para alertas de malware.

Envía alertas a N8N SOLO cuando se detecta malware (result == 'malicious').
Las URLs del webhook se configuran vía variables de entorno.
"""

from __future__ import annotations

import getpass
import json
import math
import os
import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib import request

from utils.logger import setup_logger

logger = setup_logger(__name__)

# ---------------------------------------------------------------------------
# n8n webhook URLs — configurables via variables de entorno
# ---------------------------------------------------------------------------
_DEFAULT_TEST_URL = (
    "https://postmeiotic-consolatory-haydee.ngrok-free.dev"
    "/webhook-test/shadownet-malware"
)
_DEFAULT_PROD_URL = (
    "https://postmeiotic-consolatory-haydee.ngrok-free.dev"
    "/webhook/shadownet-malware"
)

TEST_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_TEST", _DEFAULT_TEST_URL)
PRODUCTION_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_PROD", _DEFAULT_PROD_URL)


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _to_bool(value: str | None, *, default: bool = False) -> bool:
    """Converts environment-like string values to bool."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _utc_timestamp() -> str:
    """Returns an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _safe_float(value: Any, *, default: float = 0.0) -> float:
    """Parses a number from heterogeneous values using a safe fallback."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
    else:
        text = str(value or "").strip()
        if not text:
            return default
        try:
            numeric = float(text.replace(",", "."))
        except ValueError:
            return default

    if not math.isfinite(numeric):
        return default
    return numeric


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class N8NIntegrationConfig:
    """Runtime config for n8n cloud integration."""

    enabled: bool = field(
        default_factory=lambda: _to_bool(os.getenv("N8N_ENABLED"), default=False)
    )
    environment: str = field(
        default_factory=lambda: os.getenv("ENVIRONMENT", "dev").strip().lower()
    )
    webhook_test: str = field(
        default_factory=lambda: os.getenv("N8N_WEBHOOK_TEST", TEST_WEBHOOK_URL).strip()
    )
    webhook_prod: str = field(
        default_factory=lambda: os.getenv("N8N_WEBHOOK_PROD", PRODUCTION_WEBHOOK_URL).strip()
    )
    timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("N8N_TIMEOUT_SECONDS", "8"))
    )

    def selected_webhook(self) -> str:
        """Selects webhook by environment (`dev` -> test, `prod` -> production)."""
        if self.environment == "prod":
            return self.webhook_prod
        return self.webhook_test


# ---------------------------------------------------------------------------
# send_scan_result — API pública para el backend
# ---------------------------------------------------------------------------

def send_scan_result(scan_result: Dict[str, Any]) -> bool:
    """
    Envía un resultado de escaneo a N8N SOLO si es malicious.

    Si el resultado no es malicious, retorna False sin hacer nada.
    Nunca lanza excepciones al caller.

    Args:
        scan_result: Dict con campos del ScanResult (file_name, result,
                     risk_level, confidence/score, scan_type, etc.)

    Returns:
        True si se envió exitosamente, False en cualquier otro caso.
    """
    result = str(scan_result.get("result", "")).strip().lower()
    if result != "malicious":
        logger.debug(
            "[ShadowNet-N8N] Skipped: result=%s (solo se envía malicious)", result
        )
        return False

    # Construyo payload en el formato final del PRD
    payload = {
        "event": "malware_detected",
        "timestamp": _utc_timestamp(),
        "file_name": str(scan_result.get("file_name", "unknown")),
        "result": "malicious",
        "risk_level": str(scan_result.get("risk_level", "high")),
        "score": _safe_float(
            scan_result.get("confidence", scan_result.get("score")),
            default=0.0,
        ),
        "scan_type": str(scan_result.get("scan_type", "single")),
        "user_id": scan_result.get("user_id", getpass.getuser()),
        "explanation": scan_result.get("explanation"),
        "system_info": {
            "os": platform.platform(),
            "hostname": socket.gethostname(),
        },
    }

    try:
        cfg = N8NIntegrationConfig()
        if not cfg.enabled:
            logger.debug("[ShadowNet-N8N] Integration disabled, skipping malicious alert")
            return False

        webhook_url = cfg.selected_webhook()
        if not webhook_url:
            logger.warning("[ShadowNet-N8N] No webhook URL configured")
            return False

        data_bytes = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        req = request.Request(
            webhook_url,
            data=data_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
            status = resp.status
            if 200 <= status < 300:
                logger.info(
                    "[ShadowNet-N8N] Malware alert enviado: %s (HTTP %d)",
                    payload["file_name"],
                    status,
                )
                return True
            logger.warning("[ShadowNet-N8N] HTTP %d al enviar alerta", status)
            return False
    except Exception as exc:
        logger.error("[ShadowNet-N8N] Error enviando alerta: %s", exc)
        return False
