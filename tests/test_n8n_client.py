from urllib import error

from core.automation.n8n_client import N8NClient, N8NClientConfig


class _FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_n8n_client_skips_when_disabled():
    client = N8NClient(N8NClientConfig(webhook_url="https://example.com", enabled=False))
    assert client.send_analysis_event({"hello": "world"}) is False


def test_n8n_client_handles_connection_error(monkeypatch):
    def _fake_urlopen(req, timeout=0):
        raise error.URLError("connection refused")

    monkeypatch.setattr("core.automation.n8n_client.request.urlopen", _fake_urlopen)
    client = N8NClient(N8NClientConfig(webhook_url="https://example.com", enabled=True))
    assert client.send_analysis_event({"hello": "world"}) is False


def test_n8n_client_success(monkeypatch):
    def _fake_urlopen(req, timeout=0):
        return _FakeResponse()

    monkeypatch.setattr("core.automation.n8n_client.request.urlopen", _fake_urlopen)
    client = N8NClient(N8NClientConfig(webhook_url="https://example.com", enabled=True))
    assert client.send_analysis_event({"hello": "world"}) is True
