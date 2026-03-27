"""
tests/test_n8n_client.py — Tests para la integración N8N.

Verifico que send_scan_result() solo envía alertas para resultados
malicious y que maneja errores sin propagarlos.
"""

import json
from unittest.mock import patch, MagicMock
from urllib import error

from core.integrations.n8n_client import (
    N8NIntegrationConfig,
    send_scan_result,
)


class _FakeResponse:
    status = 200
    def __enter__(self):
        return self
    def __exit__(self, *a):
        pass


# ---------------------------------------------------------------------------
# Filtro malicious-only
# ---------------------------------------------------------------------------

def test_send_scan_result_skips_benign():
    """No envía nada si result != malicious."""
    assert send_scan_result({"result": "benign", "file_name": "test.exe"}) is False


def test_send_scan_result_skips_suspicious():
    """No envía nada si result == suspicious."""
    assert send_scan_result({"result": "suspicious", "file_name": "test.exe"}) is False


def test_send_scan_result_skips_empty():
    """No envía nada si result está vacío."""
    assert send_scan_result({}) is False


# ---------------------------------------------------------------------------
# Envío exitoso para malicious
# ---------------------------------------------------------------------------

@patch("core.integrations.n8n_client.request.urlopen")
@patch("core.integrations.n8n_client.N8NIntegrationConfig")
def test_send_scan_result_sends_malicious(mock_config_cls, mock_urlopen):
    """Envía alerta cuando result == malicious y N8N está habilitado."""
    cfg = MagicMock()
    cfg.enabled = True
    cfg.selected_webhook.return_value = "https://example.com/webhook"
    cfg.timeout_seconds = 5
    mock_config_cls.return_value = cfg
    mock_urlopen.return_value = _FakeResponse()

    result = send_scan_result({
        "result": "malicious",
        "file_name": "malware.exe",
        "risk_level": "high",
        "confidence": 0.95,
        "scan_type": "single",
    })

    assert result is True
    mock_urlopen.assert_called_once()
    # Verifico payload
    call_args = mock_urlopen.call_args
    req = call_args[0][0]
    payload = json.loads(req.data.decode("utf-8"))
    assert payload["event"] == "malware_detected"
    assert payload["result"] == "malicious"
    assert payload["file_name"] == "malware.exe"
    assert payload["score"] == 0.95
    assert "system_info" in payload


# ---------------------------------------------------------------------------
# N8N deshabilitado
# ---------------------------------------------------------------------------

@patch("core.integrations.n8n_client.N8NIntegrationConfig")
def test_send_scan_result_disabled(mock_config_cls):
    """No envía si N8N está deshabilitado, incluso para malicious."""
    cfg = MagicMock()
    cfg.enabled = False
    mock_config_cls.return_value = cfg

    result = send_scan_result({
        "result": "malicious",
        "file_name": "malware.exe",
    })
    assert result is False


# ---------------------------------------------------------------------------
# Error de red
# ---------------------------------------------------------------------------

@patch("core.integrations.n8n_client.request.urlopen")
@patch("core.integrations.n8n_client.N8NIntegrationConfig")
def test_send_scan_result_network_error(mock_config_cls, mock_urlopen):
    """Maneja errores de red sin propagar excepciones."""
    cfg = MagicMock()
    cfg.enabled = True
    cfg.selected_webhook.return_value = "https://example.com/webhook"
    cfg.timeout_seconds = 5
    mock_config_cls.return_value = cfg
    mock_urlopen.side_effect = error.URLError("Connection refused")

    result = send_scan_result({
        "result": "malicious",
        "file_name": "malware.exe",
    })
    assert result is False
