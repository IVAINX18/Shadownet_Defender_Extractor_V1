from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib import error, request
from urllib.parse import urlparse

from telemetry_client import TelemetryClient
from utils.logger import setup_logger

logger = setup_logger(__name__)
_DEFAULT_RECOMMENDED_ACTION = "Revisar resultado ML y aplicar playbook SOC."


def _to_bool(value: str | None, *, default: bool = False) -> bool:
    """Converts environment-like string values to bool."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _utc_timestamp() -> str:
    """Returns an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _safe_model_version(manifest_path: Path = Path("model_manifest.json")) -> str:
    """Reads model version from manifest with safe fallback."""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return "unknown"
    version = data.get("version")
    return str(version) if version else "unknown"


def _safe_sha256(file_path: str | None) -> str:
    """Returns SHA256 from file path when available, otherwise a placeholder."""
    if not file_path:
        return "dato_no_disponible"
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return "dato_no_disponible"

    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _risk_level_from_score(score: float) -> str:
    """Maps ML score to operational risk level labels."""
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.70:
        return "HIGH"
    if score >= 0.50:
        return "MEDIUM"
    return "LOW"


def _confidence_to_numeric(value: Any) -> float:
    """Normalizes confidence to numeric value expected by downstream automation."""
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip().lower()
    if text == "high":
        return 0.97
    if text == "medium":
        return 0.75
    if text == "low":
        return 0.55
    return 0.50


def _safe_first_recommendation(llm_explanation: str | None) -> str:
    """Extracts first recommendation from LLM JSON response when possible."""
    if not llm_explanation:
        return _DEFAULT_RECOMMENDED_ACTION
    try:
        data = json.loads(llm_explanation)
    except json.JSONDecodeError:
        return _DEFAULT_RECOMMENDED_ACTION
    if not isinstance(data, dict):
        return _DEFAULT_RECOMMENDED_ACTION
    recommendations = data.get("recomendaciones")
    if isinstance(recommendations, list) and recommendations:
        first = recommendations[0]
        if isinstance(first, str) and first.strip():
            return first.strip()
    return _DEFAULT_RECOMMENDED_ACTION


def extract_recommended_action_from_llm_output(
    llm_output: Dict[str, Any] | None,
) -> Optional[str]:
    """
    Extracts a recommendation from rich LLM outputs when available.

    Supports both:
    - `parsed_response.recomendaciones` (preferred)
    - JSON text in `response_text`
    """
    if not isinstance(llm_output, dict):
        return None

    parsed_response = llm_output.get("parsed_response")
    if isinstance(parsed_response, dict):
        recommendations = parsed_response.get("recomendaciones")
        if isinstance(recommendations, list):
            for candidate in recommendations:
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()

    response_text = llm_output.get("response_text")
    if isinstance(response_text, str):
        candidate = _safe_first_recommendation(response_text)
        if candidate != _DEFAULT_RECOMMENDED_ACTION:
            return candidate

    return None


@dataclass
class N8NIntegrationConfig:
    """Runtime config for n8n cloud integration."""

    enabled: bool = field(default_factory=lambda: _to_bool(os.getenv("N8N_ENABLED"), default=False))
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", "dev").strip().lower())
    webhook_test: str = field(default_factory=lambda: os.getenv("N8N_WEBHOOK_TEST", "").strip())
    webhook_prod: str = field(default_factory=lambda: os.getenv("N8N_WEBHOOK_PROD", "").strip())
    timeout_seconds: int = field(default_factory=lambda: int(os.getenv("N8N_TIMEOUT_SECONDS", "8")))

    def selected_webhook(self) -> str:
        """Selects webhook by environment (`dev` -> test, `prod` -> production)."""
        if self.environment == "prod":
            return self.webhook_prod
        return self.webhook_test


def build_detection_payload(
    scan_result: Dict[str, Any],
    *,
    llm_explanation: Optional[str] = None,
    recommended_action: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Builds the standardized detection payload consumed by n8n workflows.
    """
    file_path = str(scan_result.get("file", ""))
    file_name = Path(file_path).name if file_path else "unknown"
    score = float(scan_result.get("score", -1.0))
    confidence_raw = scan_result.get("confidence", "Low")
    confidence_value = _confidence_to_numeric(confidence_raw)
    risk_level = _risk_level_from_score(score)
    llm_text = llm_explanation or "dato_no_disponible"

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _utc_timestamp(),
        "detection": {
            "file_name": file_name,
            "file_hash": _safe_sha256(file_path),
            "file_path": file_path or "dato_no_disponible",
        },
        "ml_analysis": {
            "score": score,
            "confidence": confidence_value,
            "model_version": _safe_model_version(),
        },
        "risk_level": risk_level,
        "llm_explanation": llm_text,
        "recommended_action": recommended_action or _safe_first_recommendation(llm_text),
        "system_info": {
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "user": getpass.getuser(),
        },
    }


def send_detection_to_n8n(
    report_json: Dict[str, Any],
    *,
    config: Optional[N8NIntegrationConfig] = None,
    telemetry: Optional[TelemetryClient] = None,
) -> bool:
    """
    Sends detection payload to n8n.

    Non-blocking contract:
    - Returns False on any delivery issue.
    - Never raises to caller.
    """
    cfg = config or N8NIntegrationConfig()
    telemetry_client = telemetry or TelemetryClient()
    risk_level = str(report_json.get("risk_level", "LOW")).upper()

    if not cfg.enabled:
        logger.debug("[ShadowNet-N8N] Skipped: integration disabled")
        telemetry_client.record_n8n_delivery(
            delivered=False,
            skipped=True,
            environment=cfg.environment,
            risk_level=risk_level,
            webhook_host="not_configured",
            reason="integration_disabled",
        )
        return False

    if cfg.environment == "dev" and risk_level == "LOW":
        logger.debug("[ShadowNet-N8N] Skipped: LOW risk in dev environment")
        telemetry_client.record_n8n_delivery(
            delivered=False,
            skipped=True,
            environment=cfg.environment,
            risk_level=risk_level,
            webhook_host="dev_filter",
            reason="dev_low_risk_filter",
        )
        return False

    webhook_url = cfg.selected_webhook()
    webhook_host = urlparse(webhook_url).netloc if webhook_url else "not_configured"
    if not webhook_url:
        logger.warning("[ShadowNet-N8N] Failed: missing webhook for environment '%s'", cfg.environment)
        telemetry_client.record_n8n_delivery(
            delivered=False,
            skipped=True,
            environment=cfg.environment,
            risk_level=risk_level,
            webhook_host=webhook_host,
            reason="missing_webhook",
        )
        return False

    logger.debug("[ShadowNet-N8N] Sending alert...")
    req = request.Request(
        webhook_url,
        data=json.dumps(report_json, ensure_ascii=True).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
            status = getattr(resp, "status", 200)
            if status >= 400:
                logger.warning("[ShadowNet-N8N] Failed: HTTP %s", status)
                telemetry_client.record_n8n_delivery(
                    delivered=False,
                    skipped=False,
                    environment=cfg.environment,
                    risk_level=risk_level,
                    webhook_host=webhook_host,
                    reason=f"http_{status}",
                )
                return False
        logger.debug("[ShadowNet-N8N] Success")
        telemetry_client.record_n8n_delivery(
            delivered=True,
            skipped=False,
            environment=cfg.environment,
            risk_level=risk_level,
            webhook_host=webhook_host,
        )
        return True
    except error.URLError as exc:
        reason = "timeout" if "timed out" in str(exc).lower() else "connection_error"
        logger.warning("[ShadowNet-N8N] Failed: %s", reason)
        telemetry_client.record_n8n_delivery(
            delivered=False,
            skipped=False,
            environment=cfg.environment,
            risk_level=risk_level,
            webhook_host=webhook_host,
            reason=reason,
        )
        return False
    except Exception as exc:  # pragma: no cover
        logger.warning("[ShadowNet-N8N] Failed: %s", exc)
        telemetry_client.record_n8n_delivery(
            delivered=False,
            skipped=False,
            environment=cfg.environment,
            risk_level=risk_level,
            webhook_host=webhook_host,
            reason="unexpected_error",
        )
        return False


class N8NClient:
    """Thin OO adapter over module-level n8n integration functions."""

    def __init__(self, config: Optional[N8NIntegrationConfig] = None, telemetry: Optional[TelemetryClient] = None):
        self.config = config or N8NIntegrationConfig()
        self.telemetry = telemetry or TelemetryClient()

    def build_detection_payload(
        self,
        scan_result: Dict[str, Any],
        *,
        llm_explanation: Optional[str] = None,
        recommended_action: Optional[str] = None,
    ) -> Dict[str, Any]:
        return build_detection_payload(
            scan_result,
            llm_explanation=llm_explanation,
            recommended_action=recommended_action,
        )

    def send_detection_to_n8n(self, report_json: Dict[str, Any]) -> bool:
        return send_detection_to_n8n(report_json, config=self.config, telemetry=self.telemetry)
