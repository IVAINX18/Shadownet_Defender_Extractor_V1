import argparse
import json

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
            "response_text": "{\"resumen_ejecutivo\":\"ok\"}",
        }


class _DummyBridgeFail:
    def explain_scan(self, scan_result, provider=None, model=None):
        raise RuntimeError("ollama no disponible")


class _DummyTelemetry:
    def record_llm_interaction(self, **kwargs):
        return None


def test_cli_scan_with_explain_success(monkeypatch, capsys):
    monkeypatch.setattr(cli, "ShadowNetEngine", lambda: _DummyEngine())
    monkeypatch.setattr(cli, "LLMAgentBridge", lambda: _DummyBridgeOk())
    monkeypatch.setattr(cli, "TelemetryClient", lambda: _DummyTelemetry())

    args = argparse.Namespace(
        file="archivo.exe",
        explain=True,
        provider="ollama",
        model="mistral",
    )
    code = cli._cmd_scan(args)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 0
    assert payload["scan_result"]["label"] == "MALWARE"
    assert payload["llm"]["provider"] == "ollama"


def test_cli_scan_with_explain_error(monkeypatch, capsys):
    monkeypatch.setattr(cli, "ShadowNetEngine", lambda: _DummyEngine())
    monkeypatch.setattr(cli, "LLMAgentBridge", lambda: _DummyBridgeFail())
    monkeypatch.setattr(cli, "TelemetryClient", lambda: _DummyTelemetry())

    args = argparse.Namespace(
        file="archivo.exe",
        explain=True,
        provider="ollama",
        model="mistral",
    )
    code = cli._cmd_scan(args)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 1
    assert "error" in payload["llm"]

