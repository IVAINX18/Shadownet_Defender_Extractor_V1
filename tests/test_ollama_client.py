import io
import json
from urllib import error

import pytest

from core.llm.ollama_client import OllamaClient, OllamaClientConfig


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_ollama_client_generate_success(monkeypatch):
    def _fake_urlopen(req, timeout=0):
        return _FakeResponse({"response": "explicacion"})

    monkeypatch.setattr("core.llm.ollama_client.request.urlopen", _fake_urlopen)
    client = OllamaClient(OllamaClientConfig(base_url="http://127.0.0.1:11434", model="mistral"))
    out = client.generate("prompt")
    assert out == "explicacion"


def test_ollama_client_generate_connection_error(monkeypatch):
    def _fake_urlopen(req, timeout=0):
        raise error.URLError("connection refused")

    monkeypatch.setattr("core.llm.ollama_client.request.urlopen", _fake_urlopen)
    client = OllamaClient()
    with pytest.raises(RuntimeError, match="No se pudo conectar a Ollama"):
        client.generate("prompt")

