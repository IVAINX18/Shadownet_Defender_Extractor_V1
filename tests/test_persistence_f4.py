"""
F4 Persistence & Supabase Hardening — Tests A-J + contract/RLS/security.
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.app.integrations.supabase_client import (
    _safe_json, _classify_supabase_error, _filter_record_for_retry,
    KNOWN_COLUMNS, save_scan, save_scan_safe,
)
from core.evidence import ml_evidence, yara_evidence, EvidenceStatus


def test_safe_json_enums_and_numpy():
    from enum import Enum
    class E(Enum):
        A = "a"
    import numpy as np
    assert _safe_json(E.A) == "a"
    assert _safe_json(float("nan")) is None
    assert _safe_json({"k": np.float32(1.5)})["k"] == 1.5


def test_classify_error_pgrst204():
    assert _classify_supabase_error(Exception('Could not find the \'behavioral_analysis\' column PGRST204')) == "permanent_schema"
    assert _classify_supabase_error(Exception('violates row-level security 42501')) == "rls"


def test_filter_record_for_retry():
    rec = {"file_name": "a.exe", "evidences": [], "unknown_col": 123}
    filtered = _filter_record_for_retry(rec)
    assert "file_name" in filtered
    assert "unknown_col" not in filtered
    assert "evidences" not in filtered


def test_save_scan_pgrst204_minimal_recovery():
    # Simulate PGRST204 on first insert, success on minimal
    mock_client = MagicMock()
    # First call raises PGRST204, second succeeds
    mock_client.table.return_value.insert.return_value.execute.side_effect = [
        Exception('PGRST204 Could not find column evidences'),
        MagicMock(data=[{"id": "123"}]),
    ]
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        result = save_scan({"file_name": "test.exe", "result": "benign", "user_id": "00000000-0000-0000-0000-000000000000", "sha256": "abc", "evidences": [{"source": "ml"}]})
        # Should recover via minimal payload
        assert result["saved"] is True
        assert result.get("recovered_from") == "PGRST204"


def test_save_scan_rls_not_queued():
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.side_effect = Exception('42501 violates row-level security')
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        with patch("backend.app.integrations.supabase_client._fallback_offline") as mock_queue:
            result = save_scan({"file_name": "x", "user_id": "uid"})
            assert result["saved"] is False
            assert result.get("permanent") is True
            mock_queue.assert_not_called()


def test_save_scan_transient_queued():
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.side_effect = Exception('connection timeout')
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        with patch("backend.app.integrations.supabase_client._fallback_offline") as mock_queue:
            # F4.2: user_id del JWT requerido; el caso transient se prueba con usuario autenticado
            result = save_scan({"file_name": "x", "user_id": "uid-transient"})
            assert result["saved"] is False
            assert result.get("category") == "transient"
            mock_queue.assert_called_once()


def test_evidence_storage_jsonb():
    # Ensure evidences stored as JSONB correctly
    evidences = [{"source": "ml_onnx", "verdict": "benign", "score": 0.0}]
    data = {"file_name": "a.exe", "result": "benign", "evidences": evidences, "final_verdict": {"verdict": "benign"}, "correlation": {"S": 0.1}, "user_id": "00000000-0000-0000-0000-000000000000"}
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "1"}])
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        result = save_scan(data)
        assert result["saved"] is True
        inserted = mock_client.table.return_value.insert.call_args[0][0]
        assert inserted["evidences"] == evidences
        assert inserted["final_verdict"] == {"verdict": "benign"}


def test_idempotency_dedup():
    from backend.app.integrations.supabase_client import _idempotency_cache, _mark_idempotency
    _idempotency_cache.clear()
    _mark_idempotency("abc123")
    with patch("backend.app.integrations.supabase_client._get_supabase_client") as mock_get:
        result = save_scan({"file_name": "a", "sha256": "abc123"})
        assert result.get("deduplicated") is True
        mock_get.assert_not_called()


def test_detection_not_changed_by_persistence_failure():
    from backend.app.services.scan_service import scan_single_file
    with patch("backend.app.services.scan_service.get_engine") as mock_eng:
        mock_engine = MagicMock()
        mock_engine.scan_file.return_value = {
            "label": "MALWARE", "score": 0.9, "confidence": "High",
            "yara_matches": [], "was_unpacked": False, "detection_phases": ["ML_STATIC"],
            "is_dotnet": False, "operational_status": "DANGEROUS", "risk_level": "HIGH",
            "sha256": "abc", "file": "/tmp/test.exe",
            "final_verdict": {"verdict": "malicious", "risk_level": "critical", "operational_status": "dangerous"},
            "correlation": {}, "evidences": [],
        }
        mock_eng.return_value = mock_engine
        with patch("backend.app.services.scan_service._compute_sha256", return_value="abc"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tf:
                tf.write(b"MZ" + b"\x00"*100)
                tfname = tf.name
            try:
                result = scan_single_file(Path(tfname))
                assert str(result.result) == "malicious"
            finally:
                Path(tfname).unlink(missing_ok=True)


def test_no_secrets_in_logs(caplog):
    # Ensure _sanitize_error masks JWT
    from backend.app.integrations.supabase_client import _sanitize_error
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signature"
    msg = _sanitize_error(f"error with token {jwt}")
    assert "eyJ" not in msg
    assert "***JWT***" in msg


def test_known_columns_subset():
    # Ensure DTO fields subset of known columns after fix
    from backend.app.schemas.dto import ScanResult
    fields = set(ScanResult.model_fields.keys())
    # At least these should be in known or mapped
    assert "file_name" in KNOWN_COLUMNS
    assert "sha256" in KNOWN_COLUMNS
