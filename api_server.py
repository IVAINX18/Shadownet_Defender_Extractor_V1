from __future__ import annotations

import asyncio
import os
import time
import threading
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse
from uuid import uuid4

from core.integrations.n8n_client import N8NClient
from core.scan_pipeline import run_scan_explain_pipeline
from core.engine import ShadowNetEngine
from llm_agent_bridge import LLMAgentBridge
from security.artifact_verifier import verify_artifacts
from telemetry_client import TelemetryClient
from utils.runtime_checks import import_optional_dependency

fastapi = import_optional_dependency("fastapi", install_profile="requirements/dev.lock.txt")
Request = fastapi.Request
JSONResponse = fastapi.responses.JSONResponse
HTTPException = fastapi.HTTPException

app = fastapi.FastAPI(title="ShadowNet Defender API", version="1.0.0")
engine = ShadowNetEngine()
telemetry = TelemetryClient()
n8n_client = N8NClient()

# LLM bridge is initialized lazily to avoid startup failures when the
# Ollama tunnel is not yet available.
_llm_bridge: LLMAgentBridge | None = None


def _get_llm_bridge() -> LLMAgentBridge:
    """Returns the shared LLM bridge, creating it on first use."""
    global _llm_bridge
    if _llm_bridge is None:
        _llm_bridge = LLMAgentBridge()
    return _llm_bridge


# Maximum upload body size (20 MB).
MAX_UPLOAD_BYTES = 20 * 1024 * 1024

# Allowed base directories for the /scan endpoint.
_ALLOWED_SCAN_DIRS = [
    Path("samples").resolve(),
    Path("/tmp/shadownet_uploads").resolve(),
]

_ENVIRONMENT = os.getenv("ENVIRONMENT", "dev").strip().lower()


def _is_path_allowed(file_path: str) -> bool:
    """Returns True if file_path is under an allowed scan directory."""
    resolved = Path(file_path).resolve()
    return any(resolved.is_relative_to(d) for d in _ALLOWED_SCAN_DIRS)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _record_scan_telemetry(file_path: str, result: Dict) -> None:
    telemetry.record_scan(
        file_path=file_path,
        status=result.get("status", "error"),
        score=float(result.get("score", -1.0)),
        label=result.get("label", "Unknown"),
        scan_time_ms=float(result.get("scan_time_ms", -1.0)),
        error=result.get("error"),
    )


def _dispatch_detection_to_n8n(
    scan_result: Dict[str, Any],
    *,
    llm_explanation: str | None = None,
    recommended_action: str | None = None,
) -> bool:
    """Builds and sends n8n payload."""
    payload = n8n_client.build_detection_payload(
        scan_result,
        llm_explanation=llm_explanation,
        recommended_action=recommended_action,
    )
    return n8n_client.send_detection_to_n8n(payload)


def _dispatch_detection_to_n8n_safe(
    scan_result: Dict[str, Any],
    *,
    llm_explanation: str | None = None,
    recommended_action: str | None = None,
    source: str,
) -> None:
    """Fire-and-forget n8n dispatch in a background thread."""
    def _send() -> None:
        try:
            _dispatch_detection_to_n8n(
                scan_result,
                llm_explanation=llm_explanation,
                recommended_action=recommended_action,
            )
        except Exception as exc:  # pragma: no cover
            telemetry.record_runtime_error(source=f"n8n_dispatch_{source}", error=str(exc))

    threading.Thread(target=_send, daemon=True).start()


def _sanitize_filename(filename: str | None) -> str:
    if not filename:
        return "uploaded.bin"
    safe_name = Path(filename).name.strip()
    if not safe_name:
        return "uploaded.bin"
    normalized = "".join(ch if (ch.isalnum() or ch in {"-", "_", "."}) else "_" for ch in safe_name)
    return normalized[:120] or "uploaded.bin"


def _safe_webhook_host(url: str) -> str:
    if not url:
        return "not_configured"
    try:
        return urlparse(url).netloc or "invalid_url"
    except Exception:
        return "invalid_url"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> Dict[str, str]:
    model_state = "loaded" if engine.model is not None else "not_loaded"
    return {"status": "ok", "model": model_state}


@app.get("/verify-model")
def verify_model(manifest: str = "model_manifest.json") -> Dict:
    ok, errors = verify_artifacts(Path("."), Path(manifest))
    telemetry.record_model_verification(ok=ok, error_count=len(errors))
    return {"ok": ok, "errors": errors}


@app.get("/scan")
def scan(file_path: str) -> JSONResponse:
    if not _is_path_allowed(file_path):
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error": "File path not allowed. Only files under 'samples/' or '/tmp/shadownet_uploads/' are accepted.",
            },
        )
    result = engine.scan_file(file_path)
    _record_scan_telemetry(file_path, result)
    _dispatch_detection_to_n8n_safe(result, source="scan")
    return JSONResponse(content=result)


@app.post("/scan-batch")
def scan_batch(file_paths: List[str]) -> JSONResponse:
    denied = [fp for fp in file_paths if not _is_path_allowed(fp)]
    if denied:
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error": f"Disallowed paths: {denied}. Only 'samples/' or '/tmp/shadownet_uploads/' accepted.",
            },
        )
    results: List[Dict] = []
    for file_path in file_paths:
        result = engine.scan_file(file_path)
        _record_scan_telemetry(file_path, result)
        _dispatch_detection_to_n8n_safe(result, source="scan_batch")
        results.append(result)
    return JSONResponse(content={"results": results})


@app.post("/llm/explain")
def llm_explain(payload: Dict) -> JSONResponse:
    provider = payload.get("provider", "ollama")
    model = payload.get("model")
    file_path = payload.get("file_path")
    scan_result = payload.get("scan_result")

    if scan_result is None:
        if not file_path:
            return JSONResponse(
                status_code=422,
                content={
                    "ok": False,
                    "error": "Provide 'scan_result' (preferred) or 'file_path' in payload.",
                    "automation": {"delivered": False},
                },
            )
        scan_result = engine.scan_file(file_path)
        _record_scan_telemetry(file_path, scan_result)

    try:
        bridge = _get_llm_bridge()
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "error": f"LLM service unavailable: {exc}",
                "automation": {"delivered": False},
            },
        )

    result = run_scan_explain_pipeline(
        scan_result,
        provider=str(provider),
        model=model,
        llm_bridge=bridge,
        n8n_client=n8n_client,
        telemetry=telemetry,
        source="llm_explain",
    )
    status = 200 if result.get("ok") else 503
    return JSONResponse(status_code=status, content=result)


@app.post("/scan/upload-explain")
async def scan_upload_explain(
    request: Request,
    filename: str | None = None,
    provider: str = "ollama",
    model: str | None = None,
) -> JSONResponse:
    # --- Guard: reject oversized uploads before reading the body ---
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_UPLOAD_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "ok": False,
                        "error": f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
                        "automation": {"delivered": False},
                    },
                )
        except ValueError:
            pass

    # Stream body with size limit
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            return JSONResponse(
                status_code=413,
                content={
                    "ok": False,
                    "error": f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
                    "automation": {"delivered": False},
                },
            )
        chunks.append(chunk)
    raw_bytes = b"".join(chunks)

    if not raw_bytes:
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error": "Request body is empty. Send raw bytes with Content-Type: application/octet-stream.",
                "automation": {"delivered": False},
            },
        )

    uploads_dir = Path("/tmp/shadownet_uploads")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _sanitize_filename(filename)
    temp_path = uploads_dir / f"{int(time.time() * 1000)}-{uuid4().hex}-{safe_name}"
    temp_path.write_bytes(raw_bytes)

    try:
        scan_result = engine.scan_file(temp_path)
        scan_result["uploaded_filename"] = safe_name
        _record_scan_telemetry(str(temp_path), scan_result)

        try:
            bridge = _get_llm_bridge()
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={
                    "ok": False,
                    "error": f"LLM service unavailable: {exc}",
                    "automation": {"delivered": False},
                },
            )

        pipeline_result = await asyncio.to_thread(
            run_scan_explain_pipeline,
            scan_result,
            provider=provider,
            model=model,
            llm_bridge=bridge,
            n8n_client=n8n_client,
            telemetry=telemetry,
            source="scan_upload_explain",
        )
        status = 200 if pipeline_result.get("ok") else 503
        return JSONResponse(status_code=status, content=pipeline_result)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


@app.get("/automation/health")
def automation_health() -> Dict[str, Any]:
    selected = n8n_client.config.selected_webhook()
    return {
        "enabled": n8n_client.config.enabled,
        "environment": n8n_client.config.environment,
        "configured": bool(selected),
        "webhook_host": _safe_webhook_host(selected),
        "timeout_seconds": n8n_client.config.timeout_seconds,
    }


@app.post("/automation/test")
def automation_test(payload: Dict | None = None) -> JSONResponse:
    if _ENVIRONMENT == "prod":
        return JSONResponse(
            status_code=403,
            content={"ok": False, "error": "Endpoint disabled in production."},
        )
    test_payload = payload or {
        "file": "/tmp/test-sample.exe",
        "score": 0.99,
        "confidence": "High",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "details": {},
    }
    if "event_id" in test_payload and "detection" in test_payload:
        delivered = n8n_client.send_detection_to_n8n(test_payload)
    else:
        built = n8n_client.build_detection_payload(
            test_payload,
            llm_explanation='{"resumen_ejecutivo":"test"}',
            recommended_action="Aislar host afectado",
        )
        delivered = n8n_client.send_detection_to_n8n(built)
        test_payload = built
    return JSONResponse(content={"ok": True, "delivered": delivered, "sent_payload": test_payload})


if __name__ == "__main__":
    uvicorn = import_optional_dependency("uvicorn", install_profile="requirements/dev.lock.txt")
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=False)
