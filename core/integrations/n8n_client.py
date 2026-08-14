"""
core/integrations/n8n_client.py — Integración con N8N para alertas de malware.

Envía alertas a N8N cuando se detecta malware o amenazas DANGEROUS.
Las URLs del webhook se configuran vía variables de entorno.

Mejoras de auditoría (Tarea 12):
  12.1 — Condición de disparo: result=="malicious" OR operational_status=="DANGEROUS"
  12.2 — Payload extendido con campos de auditoría
  12.3 — Retry exponencial (1s, 2s) en HTTP >= 500 (máx 2 reintentos)
  12.4 — Sanitización de payload con _safe_json antes de enviar
"""

from __future__ import annotations

import getpass
import json
import math
import os
import platform
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib import request
from urllib.error import HTTPError, URLError

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

# Retry config
_MAX_RETRIES = 2
_BACKOFF_BASE_SECONDS = 1  # 1s, 2s (exponencial)


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


# 12.4 — Serialización segura de NaN/Inf (idéntica a supabase_client)
def _safe_json(obj: Any) -> Any:
    """Reemplaza NaN/Inf por None recursivamente para serialización segura."""
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    if isinstance(obj, dict):
        return {k: _safe_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_safe_json(v) for v in obj]
    return obj


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
# 12.3 — Retry con backoff exponencial
# ---------------------------------------------------------------------------

def _send_webhook_with_retry(
    webhook_url: str,
    payload: Dict[str, Any],
    *,
    timeout: int = 8,
    max_retries: int = _MAX_RETRIES,
) -> bool:
    """
    Envía payload JSON al webhook con retry exponencial en HTTP >= 500.

    Backoff: 1s, 2s (máx 2 reintentos).
    Solo reintenta en errores de servidor (5xx), no en errores de cliente (4xx).

    Args:
        webhook_url: URL del webhook de n8n.
        payload: Diccionario con el payload a enviar.
        timeout: Timeout HTTP en segundos.
        max_retries: Máximo de reintentos en error 5xx.

    Returns:
        True si se envió exitosamente (2xx), False en cualquier otro caso.
    """
    # 12.4 — Sanitizar payload antes de enviar
    safe_payload = _safe_json(payload)
    data_bytes = json.dumps(safe_payload, ensure_ascii=True, default=str).encode("utf-8")

    for attempt in range(1 + max_retries):  # 1 intento original + retries
        try:
            req = request.Request(
                webhook_url,
                data=data_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                if 200 <= status < 300:
                    logger.info(
                        "[ShadowNet-N8N] Alerta enviada: %s (HTTP %d, intento %d)",
                        payload.get("file_name", "unknown"),
                        status,
                        attempt + 1,
                    )
                    return True

                # HTTP 4xx — error de cliente, no reintentar
                if 400 <= status < 500:
                    logger.warning(
                        "[ShadowNet-N8N] HTTP %d (error de cliente), no reintentando", status
                    )
                    return False

        except HTTPError as exc:
            status_code = exc.code
            if status_code >= 500 and attempt < max_retries:
                # Error de servidor — reintentar con backoff
                wait = _BACKOFF_BASE_SECONDS * (2 ** attempt)
                logger.warning(
                    "[ShadowNet-N8N] HTTP %d en intento %d/%d, reintentando en %ds...",
                    status_code, attempt + 1, 1 + max_retries, wait,
                )
                time.sleep(wait)
                continue
            else:
                logger.error(
                    "[ShadowNet-N8N] HTTP %d tras %d intentos", status_code, attempt + 1
                )
                return False

        except URLError as exc:
            # Error de red — reintentar
            if attempt < max_retries:
                wait = _BACKOFF_BASE_SECONDS * (2 ** attempt)
                logger.warning(
                    "[ShadowNet-N8N] Error de red en intento %d/%d: %s, reintentando en %ds...",
                    attempt + 1, 1 + max_retries, exc.reason, wait,
                )
                time.sleep(wait)
                continue
            else:
                logger.error(
                    "[ShadowNet-N8N] Error de red tras %d intentos: %s",
                    attempt + 1, exc.reason,
                )
                return False

        except Exception as exc:
            logger.error("[ShadowNet-N8N] Error inesperado: %s", exc)
            return False

    return False


# ---------------------------------------------------------------------------
# send_scan_result — API pública para el backend
# ---------------------------------------------------------------------------

def send_scan_result(scan_result: Dict[str, Any]) -> bool:
    """
    Envía un resultado de escaneo a N8N si es malicious o DANGEROUS.

    12.1 — Condición: result=="malicious" OR operational_status=="DANGEROUS"

    Nunca lanza excepciones al caller.

    Args:
        scan_result: Dict con campos del ScanResult (file_name, result,
                     risk_level, confidence/score, scan_type, etc.)

    Returns:
        True si se envió exitosamente, False en cualquier otro caso.
    """
    # 12.1 — Condición de disparo ampliada
    result_val = str(scan_result.get("result", "")).strip().lower()
    op_status = str(scan_result.get("operational_status", "")).strip().upper()
    should_alert = (result_val == "malicious") or (op_status == "DANGEROUS")

    if not should_alert:
        logger.debug(
            "[ShadowNet-N8N] Skipped: result=%s operational_status=%s",
            result_val, op_status,
        )
        return False

    # Determinar el tipo de evento
    if result_val == "malicious" and op_status == "DANGEROUS":
        event_type = "malware_critical"
    elif op_status == "DANGEROUS":
        event_type = "dangerous_detected"
    else:
        event_type = "malware_detected"

    # 12.2 — Payload extendido con campos de auditoría
    payload = {
        "event": event_type,
        "timestamp": _utc_timestamp(),
        "file_name": str(scan_result.get("file_name", "unknown")),
        "result": str(scan_result.get("result", "")),
        "risk_level": str(scan_result.get("risk_level", "high")),
        "score": _safe_float(
            scan_result.get("confidence", scan_result.get("score")),
            default=0.0,
        ),
        "scan_type": str(scan_result.get("scan_type", "single")),
        "user_id": scan_result.get("user_id", getpass.getuser()),
        "user_email": scan_result.get("user_email", ""),
        "explanation": scan_result.get("explanation"),
        "system_info": {
            "os": platform.platform(),
            "hostname": socket.gethostname(),
        },
        # ── Campos de auditoría extendidos (12.2) ─────────────────────
        "operational_status": op_status,
        "risk_score": _safe_float(scan_result.get("risk_score")),
        "detection_phases": scan_result.get("detection_phases", []),
        "top_family": scan_result.get("top_family"),
        "injection_detected": bool(scan_result.get("injection_detected", False)),
        "persistence_detected": bool(scan_result.get("persistence_detected", False)),
    }

    try:
        cfg = N8NIntegrationConfig()
        if not cfg.enabled:
            logger.debug("[ShadowNet-N8N] Integration disabled, skipping alert")
            return False

        webhook_url = cfg.selected_webhook()
        if not webhook_url:
            logger.warning("[ShadowNet-N8N] No webhook URL configured")
            return False

        # 12.3 — Enviar con retry exponencial
        return _send_webhook_with_retry(
            webhook_url,
            payload,
            timeout=cfg.timeout_seconds,
        )

    except Exception as exc:
        logger.error("[ShadowNet-N8N] Error enviando alerta: %s", exc)
        return False
