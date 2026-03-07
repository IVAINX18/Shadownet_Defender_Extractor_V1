import json
from urllib import error

from core.integrations.n8n_client import (
    N8NClient,
    N8NIntegrationConfig,
    build_detection_payload,
    send_detection_to_n8n,
)
from telemetry_client import TelemetryClient


class _FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_build_detection_payload_structure():
    payload = build_detection_payload(
        {
            "file": "/tmp/sample.exe",
            "score": 0.91,
            "confidence": "High",
            "timestamp": "2026-02-18 20:00:00",
            "details": {},
        },
        llm_report={
            "resumen_ejecutivo": "Riesgo alto",
            "explicacion_tecnica": "Imports sospechosos",
            "justificacion_matematica": "score >= 0.5",
            "recommended_action": "Aislar host",
            "indicadores_clave": ["score alto"],
        },
    )
    assert payload["risk_level"] == "CRITICAL"
    assert "event_id" in payload
    assert "file_name" in payload
    assert "ml_score" in payload
    assert "hostname" in payload
    llm_report = json.loads(payload["llm_report"])
    assert llm_report["recommended_action"] == "Aislar host"


def test_build_detection_payload_normalizes_blank_numeric_inputs():
    payload = build_detection_payload(
        {
            "file": "",
            "score": "",
            "confidence": "",
            "details": {},
        },
        llm_report="",
    )
    assert payload["ml_score"] == 0.0
    assert payload["confidence"] == 0.50
    assert payload["file_name"] == "unknown"
    assert payload["file_path"] == "dato_no_disponible"
    llm_report = json.loads(payload["llm_report"])
    assert llm_report["recommended_action"] == "Revisar resultado ML y aplicar playbook SOC."


def test_send_detection_to_n8n_skips_low_risk_in_dev(tmp_path):
    telemetry = TelemetryClient(log_path=tmp_path / "telemetry.jsonl")
    report = {
        "risk_level": "LOW",
        "detection": {"file_name": "sample.exe", "file_hash": "x", "file_path": "/tmp/sample.exe"},
    }
    sent = send_detection_to_n8n(
        report,
        config=N8NIntegrationConfig(
            enabled=True,
            environment="dev",
            webhook_test="https://example.test",
            webhook_prod="https://example.prod",
            timeout_seconds=3,
        ),
        telemetry=telemetry,
    )
    assert sent is False


def test_send_detection_to_n8n_uses_prod_webhook(monkeypatch, tmp_path):
    target = {"url": "", "payload": None}

    def _fake_urlopen(req, timeout=0):
        target["url"] = req.full_url
        target["payload"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse()

    monkeypatch.setattr("core.integrations.n8n_client.request.urlopen", _fake_urlopen)
    telemetry = TelemetryClient(log_path=tmp_path / "telemetry.jsonl")
    sent = send_detection_to_n8n(
        {"risk_level": "HIGH"},
        config=N8NIntegrationConfig(
            enabled=True,
            environment="prod",
            webhook_test="https://example.test",
            webhook_prod="https://example.prod",
            timeout_seconds=3,
        ),
        telemetry=telemetry,
    )
    assert sent is True
    assert target["url"] == "https://example.prod"


def test_send_detection_to_n8n_normalizes_prebuilt_payload(monkeypatch, tmp_path):
    target = {"payload": None}

    def _fake_urlopen(req, timeout=0):
        target["payload"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse()

    monkeypatch.setattr("core.integrations.n8n_client.request.urlopen", _fake_urlopen)
    telemetry = TelemetryClient(log_path=tmp_path / "telemetry.jsonl")
    sent = send_detection_to_n8n(
        {
            "event_id": "abc-123",
            "timestamp": "2026-02-20 19:47:37",
            "ml_score": "",
            "confidence": "",
            "risk_level": "LOW",
            "llm_report": "",
        },
        config=N8NIntegrationConfig(
            enabled=True,
            environment="prod",
            webhook_test="https://example.test",
            webhook_prod="https://example.prod",
            timeout_seconds=3,
        ),
        telemetry=telemetry,
    )
    assert sent is True
    assert target["payload"]["ml_score"] == 0.0
    assert target["payload"]["confidence"] == 0.50
    assert "recommended_action" not in target["payload"]
    assert "llm_explanation" not in target["payload"]


def test_n8n_client_handles_connection_error(monkeypatch, tmp_path):
    def _fake_urlopen(req, timeout=0):
        raise error.URLError("connection refused")

    monkeypatch.setattr("core.integrations.n8n_client.request.urlopen", _fake_urlopen)
    client = N8NClient(
        N8NIntegrationConfig(
            enabled=True,
            environment="prod",
            webhook_test="https://example.test",
            webhook_prod="https://example.prod",
            timeout_seconds=3,
        ),
        telemetry=TelemetryClient(log_path=tmp_path / "telemetry.jsonl"),
    )
    sent = client.send_detection_to_n8n({"risk_level": "HIGH"})
    assert sent is False
