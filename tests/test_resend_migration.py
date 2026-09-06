"""
tests/test_resend_migration.py — Validacion n8n → Supabase+Resend (8 criterios).

Cubre:
 1. malicious → genera alerta (send_scan_result true, save_scan alert_sent=false)
 2. DANGEROUS → genera alerta (operational_status DANGEROUS)
 3. benign/SAFE → NO genera alerta
 4. ausencia de email → no rompe pipeline (False, no excepcion)
 5. error de Resend (Edge Function 5xx) → se maneja (mock)
 6. idempotencia → no duplicados (sha256 ventana 60s)
 7. INSERT scan_results → activa flujo (save_scan construye record correcto)
 8. rollback → N8N_ENABLED=false desactiva n8n pero Supabase sigue funcionando
"""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch

import pytest

from backend.app.integrations.supabase_client import (
    _check_idempotency,
    _mark_idempotency,
    _idempotency_cache,
    save_scan,
    _safe_json,
)
from core.integrations.n8n_client import send_scan_result, _safe_json as n8n_safe_json


# ---------------------------------------------------------------------------
# Helper: payload base
# ---------------------------------------------------------------------------
def _base_record(**overrides):
    base = {
        "file_name": "evil.exe",
        "scan_type": "single",
        "result": "malicious",
        "risk_level": "high",
        "confidence": 0.97,
        "score": 0.97,
        "operational_status": "DANGEROUS",
        "sha256": "a" * 64,
        "user_id": "user-001",
        "user_email": "test@example.com",
        "yara_matches": [],
        "detection_phases": [],
        "offline": False,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. malicious → genera alerta via n8n (filtrado actual)
# ---------------------------------------------------------------------------
def test_criterio1_malicious_genera_alerta():
    with patch("core.integrations.n8n_client.N8NIntegrationConfig") as mock_cfg_cls, \
         patch("core.integrations.n8n_client.request.urlopen") as mock_urlopen:
        mock_cfg = MagicMock()
        mock_cfg.enabled = True
        mock_cfg.selected_webhook.return_value = "https://example.com/webhook"
        mock_cfg.timeout_seconds = 8
        mock_cfg_cls.return_value = mock_cfg
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        rec = _base_record(result="malicious", operational_status="DANGEROUS")
        assert send_scan_result(rec) is True


# ---------------------------------------------------------------------------
# 2. DANGEROUS → genera alerta aunque result no sea malicious
# ---------------------------------------------------------------------------
def test_criterio2_dangerous_genera_alerta():
    with patch("core.integrations.n8n_client.N8NIntegrationConfig") as mock_cfg_cls, \
         patch("core.integrations.n8n_client.request.urlopen") as mock_urlopen:
        mock_cfg = MagicMock()
        mock_cfg.enabled = True
        mock_cfg.selected_webhook.return_value = "https://example.com/webhook"
        mock_cfg.timeout_seconds = 8
        mock_cfg_cls.return_value = mock_cfg
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        rec = _base_record(result="suspicious", operational_status="DANGEROUS")
        assert send_scan_result(rec) is True


# ---------------------------------------------------------------------------
# 3. benign/SAFE → NO genera alerta
# ---------------------------------------------------------------------------
def test_criterio3_benign_no_genera_alerta():
    # No necesita mock porque no debe llegar a HTTP
    rec = _base_record(result="benign", operational_status="CLEAN")
    assert send_scan_result(rec) is False
    rec2 = _base_record(result="suspicious", operational_status="SAFE")
    assert send_scan_result(rec2) is False


# ---------------------------------------------------------------------------
# 4. ausencia de email → no rompe pipeline
# ---------------------------------------------------------------------------
def test_criterio4_ausencia_email_no_rompe():
    # send_scan_result no debe lanzar excepcion aunque falte user_email
    # Para malicious con email vacio, igual intenta enviar (payload user_email="")
    with patch("core.integrations.n8n_client.N8NIntegrationConfig") as mock_cfg_cls, \
         patch("core.integrations.n8n_client.request.urlopen") as mock_urlopen:
        mock_cfg = MagicMock()
        mock_cfg.enabled = True
        mock_cfg.selected_webhook.return_value = "https://example.com/webhook"
        mock_cfg.timeout_seconds = 8
        mock_cfg_cls.return_value = mock_cfg
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        rec = _base_record(result="malicious", user_email="", user_id="user-001")
        # No debe lanzar
        result = send_scan_result(rec)
        assert isinstance(result, bool)

    # save_scan sin email tampoco debe romper (cae a fallback offline si Supabase no configurado)
    rec2 = _base_record(user_email=None)
    # Mock supabase para no requerir credenciales reales
    with patch("backend.app.integrations.supabase_client._get_supabase_client") as mock_client:
        mock_table = MagicMock()
        mock_table.insert.return_value.execute.return_value.data = [{"id": "uuid-1"}]
        mock_c = MagicMock()
        mock_c.table.return_value = mock_table
        mock_client.return_value = mock_c
        # Limpiar idempotencia
        _idempotency_cache.clear()
        res = save_scan(rec2)
        assert res["saved"] is True


# ---------------------------------------------------------------------------
# 5. error de Resend → se maneja (simulado como HTTP 500 en n8n)
# ---------------------------------------------------------------------------
def test_criterio5_error_resend_manejado():
    # n8n retry: si HTTP 500, reintenta y luego retorna False sin excepcion
    with patch("core.integrations.n8n_client.N8NIntegrationConfig") as mock_cfg_cls, \
         patch("core.integrations.n8n_client.request.urlopen") as mock_urlopen, \
         patch("core.integrations.n8n_client.time.sleep"):
        mock_cfg = MagicMock()
        mock_cfg.enabled = True
        mock_cfg.selected_webhook.return_value = "https://example.com/webhook"
        mock_cfg.timeout_seconds = 2
        mock_cfg_cls.return_value = mock_cfg
        # Simular HTTP 500 persistente
        from urllib.error import HTTPError
        mock_urlopen.side_effect = HTTPError("https://example.com", 500, "Server Error", None, None)
        rec = _base_record(result="malicious")
        assert send_scan_result(rec) is False

    # _safe_json maneja NaN/Inf sin romper serializacion (usado por Resend payload)
    assert n8n_safe_json(float("nan")) is None
    assert n8n_safe_json(float("inf")) is None
    assert _safe_json({"score": float("nan")}) == {"score": None}


# ---------------------------------------------------------------------------
# 6. idempotencia → no duplicados
# ---------------------------------------------------------------------------
def test_criterio6_idempotencia_sha256():
    _idempotency_cache.clear()
    sha = "b" * 64
    rec = _base_record(sha256=sha)
    with patch("backend.app.integrations.supabase_client._get_supabase_client") as mock_client:
        mock_table = MagicMock()
        mock_table.insert.return_value.execute.return_value.data = [{"id": "uuid-2"}]
        mock_c = MagicMock()
        mock_c.table.return_value = mock_table
        mock_client.return_value = mock_c

        res1 = save_scan(rec)
        assert res1["saved"] is True
        assert res1.get("deduplicated") is not True

        # Segundo insert inmediato mismo sha256 → deduplicado
        res2 = save_scan(rec)
        assert res2["saved"] is True
        assert res2.get("deduplicated") is True
        assert "Duplicado" in res2.get("reason", "")

    # Tras ventana expirada debe permitir de nuevo (simular tiempo)
    _idempotency_cache[sha] = time.time() - 70
    with patch("backend.app.integrations.supabase_client._get_supabase_client") as mock_client:
        mock_table = MagicMock()
        mock_table.insert.return_value.execute.return_value.data = [{"id": "uuid-3"}]
        mock_c = MagicMock()
        mock_c.table.return_value = mock_table
        mock_client.return_value = mock_c
        res3 = save_scan(rec)
        assert res3.get("deduplicated") is not True
    _idempotency_cache.clear()


# ---------------------------------------------------------------------------
# 7. INSERT scan_results → activa flujo (record construido correctamente)
# ---------------------------------------------------------------------------
def test_criterio7_insert_construye_record_con_alert_sent():
    rec = _base_record()
    with patch("backend.app.integrations.supabase_client._get_supabase_client") as mock_client:
        mock_table = MagicMock()
        mock_exec = MagicMock()
        mock_exec.data = [{"id": "uuid-4"}]
        mock_insert_ret = MagicMock()
        mock_insert_ret.execute.return_value = mock_exec
        mock_table.insert.return_value = mock_insert_ret
        mock_c = MagicMock()
        mock_c.table.return_value = mock_table
        mock_client.return_value = mock_c
        _idempotency_cache.clear()

        res = save_scan(rec)
        assert res["saved"] is True
        # Primer insert es a scan_results; capturamos su argumento
        first_call_record = mock_table.insert.call_args_list[0][0][0]
        assert "alert_sent" in first_call_record
        assert first_call_record["alert_sent"] is False
        assert first_call_record["operational_status"] == "DANGEROUS"
        assert first_call_record["sha256"] == "a" * 64

    _idempotency_cache.clear()


# ---------------------------------------------------------------------------
# 8. rollback → N8N_ENABLED=false desactiva n8n pero Supabase sigue
# ---------------------------------------------------------------------------
def test_criterio8_rollback_n8n_disabled_supabase_sigue():
    # n8n deshabilitado → send_scan_result retorna False
    with patch.dict(os.environ, {"N8N_ENABLED": "false"}, clear=False):
        rec = _base_record(result="malicious")
        assert send_scan_result(rec) is False

    # Supabase sigue guardando aunque n8n este off
    rec2 = _base_record()
    with patch("backend.app.integrations.supabase_client._get_supabase_client") as mock_client:
        mock_table = MagicMock()
        mock_table.insert.return_value.execute.return_value.data = [{"id": "uuid-5"}]
        mock_c = MagicMock()
        mock_c.table.return_value = mock_table
        mock_client.return_value = mock_c
        _idempotency_cache.clear()
        res = save_scan(rec2)
        assert res["saved"] is True
    _idempotency_cache.clear()
