from urllib import error

from core.integrations.n8n_client import (
    N8NClient,
    N8NIntegrationConfig,
    build_detection_payload,
    extract_recommended_action_from_llm_output,
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
        llm_explanation='{"recomendaciones":["Aislar host"]}',
    )
    assert payload["risk_level"] == "CRITICAL"
    assert "event_id" in payload
    assert "detection" in payload
    assert "ml_analysis" in payload
    assert "system_info" in payload


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
    target = {"url": ""}

    def _fake_urlopen(req, timeout=0):
        target["url"] = req.full_url
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


def test_extract_recommended_action_from_llm_output_prefers_parsed_response():
    llm_output = {
        "response_text": '{"recomendaciones": ["Texto en bruto"]}',
        "parsed_response": {"recomendaciones": ["Aislar host comprometido"]},
    }
    assert (
        extract_recommended_action_from_llm_output(llm_output)
        == "Aislar host comprometido"
    )


def test_extract_recommended_action_from_llm_output_uses_json_text_fallback():
    llm_output = {
        "response_text": '{"recomendaciones": ["Rotar credenciales"]}',
    }
    assert extract_recommended_action_from_llm_output(llm_output) == "Rotar credenciales"
