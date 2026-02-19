from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class TelemetryClient:
    """Lightweight JSONL telemetry writer for local operational metrics."""

    log_path: Path = Path("logs/telemetry.jsonl")

    def __post_init__(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _hash_text(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()

    def _write_event(self, event: Dict[str, Any]) -> None:
        payload = dict(event)
        payload.setdefault("timestamp_unix", time.time())
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=True) + "\n")

    def record_scan(
        self,
        *,
        file_path: str,
        status: str,
        score: float,
        label: str,
        scan_time_ms: float,
        model_version: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        self._write_event(
            {
                "event": "scan",
                "file_hash": self._hash_text(file_path),
                "status": status,
                "score": score,
                "label": label,
                "scan_time_ms": scan_time_ms,
                "model_version": model_version,
                "error": error,
            }
        )

    def record_model_verification(self, *, ok: bool, error_count: int) -> None:
        self._write_event(
            {
                "event": "model_verification",
                "ok": ok,
                "error_count": error_count,
            }
        )

    def record_runtime_error(self, *, source: str, error: str) -> None:
        self._write_event(
            {
                "event": "runtime_error",
                "source": source,
                "error": error,
            }
        )

    def record_llm_interaction(
        self,
        *,
        provider: str,
        model: str,
        ok: bool,
        latency_ms: float,
        error: Optional[str] = None,
    ) -> None:
        self._write_event(
            {
                "event": "llm_interaction",
                "provider": provider,
                "model": model,
                "ok": ok,
                "latency_ms": latency_ms,
                "error": error,
            }
        )

    def record_n8n_delivery(
        self,
        *,
        delivered: bool,
        skipped: bool,
        environment: str,
        risk_level: str,
        webhook_host: str,
        reason: Optional[str] = None,
    ) -> None:
        """Tracks automation delivery attempts to n8n."""
        self._write_event(
            {
                "event": "n8n_delivery",
                "delivered": delivered,
                "skipped": skipped,
                "environment": environment,
                "risk_level": risk_level,
                "webhook_host": webhook_host,
                "reason": reason,
            }
        )
