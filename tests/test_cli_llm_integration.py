import argparse
from io import StringIO

from rich.console import Console

import cli


class _DummyEngine:
    def scan_file(self, file_path):
        return {
            "file": file_path,
            "status": "detected",
            "score": 0.91,
            "label": "MALWARE",
            "confidence": "High",
            "scan_time_ms": 10.0,
            "details": {},
        }


class _DummyBridgeOk:
    def explain_scan(self, scan_result, provider=None, model=None):
        return {
            "provider": provider or "ollama",
            "model": model or "mistral",
            "response_text": '{"resumen_ejecutivo":"ok"}',
        }


class _DummyBridgeFail:
    def explain_scan(self, scan_result, provider=None, model=None):
        raise RuntimeError("ollama no disponible")


class _DummyTelemetry:
    def record_llm_interaction(self, **kwargs):
        return None

    def record_scan(self, **kwargs):
        return None

    def record_n8n_delivery(self, **kwargs):
        return None

    def record_runtime_error(self, **kwargs):
        return None


class _DummyN8NClient:
    """Stub that avoids any real n8n interaction."""

    def build_detection_payload(self, *a, **kw):
        return {}

    def send_detection_to_n8n(self, *a, **kw):
        return False


def test_cli_scan_with_explain_success(monkeypatch):
    """CLI scan --explain prints scan table and LLM panels (Rich output)."""
    captured = StringIO()
    test_console = Console(file=captured, force_terminal=False, width=200)

    monkeypatch.setattr(cli, "ShadowNetEngine", lambda: _DummyEngine())
    monkeypatch.setattr(cli, "LLMAgentBridge", lambda: _DummyBridgeOk())
    monkeypatch.setattr(cli, "TelemetryClient", lambda: _DummyTelemetry())
    monkeypatch.setattr(cli, "N8NClient", lambda: _DummyN8NClient())
    monkeypatch.setattr(cli, "console", test_console)

    args = argparse.Namespace(
        file="archivo.exe",
        explain=True,
        provider="ollama",
        model="mistral",
    )
    code = cli._cmd_scan(args)
    output = captured.getvalue()
    assert code == 0
    assert "MALWARE" in output
    assert "0.91" in output


def test_cli_scan_with_explain_error(monkeypatch):
    """CLI scan --explain surfaces LLM error in Rich output and returns code 1."""
    captured = StringIO()
    test_console = Console(file=captured, force_terminal=False, width=200)

    monkeypatch.setattr(cli, "ShadowNetEngine", lambda: _DummyEngine())
    monkeypatch.setattr(cli, "LLMAgentBridge", lambda: _DummyBridgeFail())
    monkeypatch.setattr(cli, "TelemetryClient", lambda: _DummyTelemetry())
    monkeypatch.setattr(cli, "N8NClient", lambda: _DummyN8NClient())
    monkeypatch.setattr(cli, "console", test_console)

    args = argparse.Namespace(
        file="archivo.exe",
        explain=True,
        provider="ollama",
        model="mistral",
    )
    code = cli._cmd_scan(args)
    output = captured.getvalue()
    assert code == 1
    # The error response is shown as JSON panel containing the error text
    assert "MALWARE" in output
