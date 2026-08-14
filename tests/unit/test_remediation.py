"""
tests/unit/test_remediation.py — Tests unitarios del RemediationEngine.

16.2 — Cubre:
  - PID < 10 rechazado
  - exe_path mismatch rechazado
  - PermissionError no propagado
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.remediation import RemediationEngine


class TestProtectedProcessRejection:
    """PID < 10 rechazado con PROTECTED_PROCESS_REJECTED."""

    @pytest.mark.parametrize("pid", [0, 1, 2, 5, 9])
    def test_rejects_pid_below_10(self, pid):
        """PIDs menores a 10 deben ser rechazados sin intentar terminación."""
        engine = RemediationEngine()
        result = engine.terminate_process(
            pid=pid,
            reason="test",
            scan_id="test-scan-001",
        )

        assert result.success is False
        assert result.error == "PROTECTED_PROCESS_REJECTED"
        assert result.pid == pid


class TestExeMismatch:
    """exe_path mismatch rechazado con EXE_MISMATCH."""

    def test_exe_mismatch_rejected(self):
        """Si el exe real no coincide con expected_exe, rechazar sin terminar."""
        engine = RemediationEngine()

        mock_proc = MagicMock()
        mock_proc.exe.return_value = "/usr/bin/python3"

        with patch("psutil.Process", return_value=mock_proc):
            result = engine.terminate_process(
                pid=12345,
                reason="test",
                scan_id="test-scan-002",
                expected_exe=Path("/opt/malware/evil.exe"),
            )

        assert result.success is False
        assert result.error == "EXE_MISMATCH"


class TestPermissionErrorNotPropagated:
    """PermissionError no propagado al caller."""

    def test_permission_error_not_propagated(self):
        """PermissionError debe quedar capturado en el resultado, no propagarse."""
        engine = RemediationEngine()

        mock_proc = MagicMock()
        mock_proc.exe.return_value = "/usr/bin/test"

        import psutil
        mock_proc.wait.side_effect = psutil.AccessDenied(pid=99999)

        with patch("psutil.Process", return_value=mock_proc), \
             patch("os.kill", side_effect=PermissionError("Operation not permitted")):
            # No debe lanzar excepción
            result = engine.terminate_process(
                pid=99999,
                reason="test",
                scan_id="test-scan-003",
            )

        # Debe retornar resultado sin propagar
        assert result.success is False
        assert "PERMISSION_DENIED" in (result.error or "")
