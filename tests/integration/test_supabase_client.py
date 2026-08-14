"""
tests/integration/test_supabase_client.py — Tests de integración del cliente Supabase.

17.2 — Cubre:
  - Telemetría completa (todos los 16 campos nuevos presentes en el record)
  - save_incident() se llama en DANGEROUS
  - Fallback a offline_service cuando Supabase no disponible
  - Idempotencia por sha256 (doble inserción con mismo sha256 → deduplicado)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# Campos nuevos de telemetría que deben estar presentes en el record
_EXPECTED_TELEMETRY_FIELDS = {
    "operational_status",
    "sha256",
    "overlay_analysis",
    "yara_matches",
    "il_behavioral",
    "dotnet_analysis",
    "detection_phases",
    "was_unpacked",
    "is_dotnet",
    "obfuscator_detected",
    "obfuscator_name",
    "injection_detected",
    "persistence_detected",
    "networking_detected",
    "credential_theft_detected",
    "behavioral_analysis",
}


class TestSupabaseTelemetryFields:
    """17.2a — Todos los 16 campos nuevos presentes en el record."""

    def test_record_has_all_telemetry_fields(self):
        """save_scan debe construir un record con todos los campos de auditoría."""
        from backend.app.integrations.supabase_client import save_scan

        data = {
            "file_name": "test.exe",
            "result": "malicious",
            "confidence": 0.95,
            "risk_level": "high",
            "operational_status": "DANGEROUS",
            "sha256": f"unique_sha_telemetry_{time.time()}",
            "overlay_analysis": {"suspicious": True},
            "yara_matches": [{"rule": "EICAR"}],
            "il_behavioral": {"threat_score": 80},
            "dotnet_analysis": {"is_dotnet": True},
            "detection_phases": ["YARA", "ML_STATIC"],
            "was_unpacked": True,
            "is_dotnet": True,
            "obfuscator_detected": True,
            "obfuscator_name": "ConfuserEx",
            "injection_detected": True,
            "persistence_detected": False,
            "networking_detected": True,
            "credential_theft_detected": False,
            "behavioral_analysis": {"pid": 123, "risk_score": 0.9},
        }

        # Capturar el record que se intentaría insertar
        captured_record = {}

        def mock_insert(record):
            captured_record.update(record)
            mock_resp = MagicMock()
            mock_resp.data = [{"id": "fake-uuid"}]
            chain = MagicMock()
            chain.execute.return_value = mock_resp
            return chain

        mock_table = MagicMock()
        mock_table.insert = mock_insert
        mock_client = MagicMock()
        mock_client.table.return_value = mock_table

        with patch("backend.app.integrations.supabase_client._get_supabase_client",
                   return_value=mock_client):
            save_scan(data)

        # Verificar que todos los campos nuevos están en el record
        missing = _EXPECTED_TELEMETRY_FIELDS - set(captured_record.keys())
        assert not missing, f"Campos faltantes en el record: {missing}"

    def test_safe_json_applied(self):
        """NaN/Inf en los datos no deben aparecer en el record (sanitizados por _safe_json)."""
        import math
        from backend.app.integrations.supabase_client import save_scan

        data = {
            "file_name": "test_nan.exe",
            "result": "benign",
            "confidence": float("nan"),  # NaN
            "risk_level": "low",
            "sha256": f"nan_test_{time.time()}",
        }

        captured_record = {}

        def mock_insert(record):
            captured_record.update(record)
            mock_resp = MagicMock()
            mock_resp.data = [{"id": "fake-uuid"}]
            chain = MagicMock()
            chain.execute.return_value = mock_resp
            return chain

        mock_table = MagicMock()
        mock_table.insert = mock_insert
        mock_client = MagicMock()
        mock_client.table.return_value = mock_table

        with patch("backend.app.integrations.supabase_client._get_supabase_client",
                   return_value=mock_client):
            save_scan(data)

        # El score NaN debe haber sido sanitizado
        score = captured_record.get("score", 0.0)
        assert score is None or (isinstance(score, float) and math.isfinite(score)), \
            f"NaN no sanitizado en score: {score}"


class TestSaveIncidentOnDangerous:
    """17.2b — save_incident() se llama automáticamente para DANGEROUS."""

    def test_incident_saved_on_dangerous(self):
        """Cuando operational_status=='DANGEROUS', debe insertarse en tabla incidents."""
        from backend.app.integrations.supabase_client import save_scan

        data = {
            "file_name": "dangerous.exe",
            "result": "malicious",
            "confidence": 0.99,
            "risk_level": "high",
            "operational_status": "DANGEROUS",
            "sha256": f"dangerous_sha_{time.time()}",
        }

        incidents_inserted = []

        def mock_table(name):
            t = MagicMock()
            if name == "scan_results":
                mock_resp = MagicMock()
                mock_resp.data = [{"id": "scan-uuid-123"}]
                chain = MagicMock()
                chain.execute.return_value = mock_resp
                t.insert.return_value = chain
            elif name == "incidents":
                def capture_insert(record):
                    incidents_inserted.append(record)
                    chain = MagicMock()
                    chain.execute.return_value = MagicMock()
                    return chain
                t.insert = capture_insert
            return t

        mock_client = MagicMock()
        mock_client.table.side_effect = mock_table

        with patch("backend.app.integrations.supabase_client._get_supabase_client",
                   return_value=mock_client):
            save_scan(data)

        assert len(incidents_inserted) == 1, "Debe insertarse exactamente 1 incidente"
        incident = incidents_inserted[0]
        assert incident.get("severity") == "critical"
        assert incident.get("operational_status") == "DANGEROUS"

    def test_no_incident_on_clean(self):
        """Para operational_status distinto de DANGEROUS, NO debe insertarse incidente."""
        from backend.app.integrations.supabase_client import save_scan

        data = {
            "file_name": "clean.exe",
            "result": "benign",
            "confidence": 0.1,
            "risk_level": "low",
            "operational_status": "CLEAN",
            "sha256": f"clean_sha_{time.time()}",
        }

        incidents_inserted = []

        def mock_table(name):
            t = MagicMock()
            if name == "scan_results":
                mock_resp = MagicMock()
                mock_resp.data = [{"id": "scan-uuid-456"}]
                chain = MagicMock()
                chain.execute.return_value = mock_resp
                t.insert.return_value = chain
            elif name == "incidents":
                def capture_insert(record):
                    incidents_inserted.append(record)
                    return MagicMock()
                t.insert = capture_insert
            return t

        mock_client = MagicMock()
        mock_client.table.side_effect = mock_table

        with patch("backend.app.integrations.supabase_client._get_supabase_client",
                   return_value=mock_client):
            save_scan(data)

        assert len(incidents_inserted) == 0, "No debe insertarse incidente para CLEAN"


class TestOfflineFallback:
    """17.2c — Fallback a offline_service cuando Supabase no disponible."""

    def test_fallback_offline_on_supabase_failure(self):
        """Cuando Supabase falla, debe encolarse en offline_service."""
        from backend.app.integrations.supabase_client import save_scan_safe

        data = {
            "file_name": "offline_test.exe",
            "result": "suspicious",
            "sha256": f"offline_sha_{time.time()}",
        }

        queued = []

        with patch("backend.app.integrations.supabase_client._get_supabase_client",
                   side_effect=RuntimeError("Supabase key not configured")), \
             patch("backend.app.services.offline_service.queue_scan",
                   side_effect=lambda d: queued.append(d)):
            result = save_scan_safe(data)

        assert result.get("saved") is False
        assert len(queued) == 1
        assert queued[0]["file_name"] == "offline_test.exe"

    def test_fallback_does_not_propagate(self):
        """save_scan_safe nunca debe propagar excepciones al caller."""
        from backend.app.integrations.supabase_client import save_scan_safe

        # Supabase falla Y offline_service también falla
        with patch("backend.app.integrations.supabase_client._get_supabase_client",
                   side_effect=Exception("total failure")), \
             patch("backend.app.services.offline_service.queue_scan",
                   side_effect=Exception("offline also failed")):
            # NO debe lanzar excepción
            result = save_scan_safe({"file_name": "test.exe"})

        assert isinstance(result, dict)
        assert result.get("saved") is False


class TestIdempotency:
    """17.2d — Idempotencia por sha256."""

    def test_same_sha256_within_60s_deduplicated(self):
        """Dos inserciones con el mismo sha256 en < 60s → la segunda es deduplicada."""
        from backend.app.integrations.supabase_client import (
            save_scan, _idempotency_cache,
        )

        sha = f"idem_sha256_{time.time()}"
        data = {
            "file_name": "idem_test.exe",
            "result": "malicious",
            "sha256": sha,
        }

        insert_count = [0]

        def mock_table(name):
            t = MagicMock()
            def counting_insert(record):
                insert_count[0] += 1
                mock_resp = MagicMock()
                mock_resp.data = [{"id": "uuid"}]
                chain = MagicMock()
                chain.execute.return_value = mock_resp
                return chain
            t.insert = counting_insert
            return t

        mock_client = MagicMock()
        mock_client.table.side_effect = mock_table

        with patch("backend.app.integrations.supabase_client._get_supabase_client",
                   return_value=mock_client):
            r1 = save_scan(data)
            r2 = save_scan(data)  # misma sha256

        assert r1.get("saved") is True
        assert r2.get("deduplicated") is True
        assert insert_count[0] == 1  # Solo UNA inserción real
