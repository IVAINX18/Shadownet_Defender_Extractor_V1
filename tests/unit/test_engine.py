"""
tests/unit/test_engine.py — Tests unitarios del motor ShadowNetEngine.

15.2 — Cubre:
  - YARA match → MALWARE
  - ONNX falla → UNKNOWN/SUSPICIOUS
  - no-PE .exe → SUSPICIOUS
  - Elevación behavioral DANGEROUS/SUSPICIOUS
  - Fase falla → pipeline continúa
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestEngineYARA:
    """YARA match → MALWARE."""

    def test_yara_match_returns_malware(self, tmp_path):
        """Si YARA detecta match, el resultado debe ser MALWARE con score 1.0."""
        test_file = tmp_path / "malware.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            # Mock de YARA que detecta match
            mock_yara = MagicMock()
            mock_yara.is_available = True
            mock_scan = MagicMock()
            mock_scan.has_matches = True
            mock_scan.threat_names = ["Trojan.Test"]
            mock_scan.categories = ["trojan"]
            mock_scan.matches = [MagicMock(rule_name="Trojan_Test", category="trojan", tags=[])]
            mock_scan.scan_time_ms = 1.0
            mock_yara.scan.return_value = mock_scan
            engine._yara_scanner = mock_yara
            engine._behavioral_shield = None

            result = {}
            result["detection_phases"] = []
            result["yara_matches"] = []
            yara_result = engine._run_yara_phase(test_file, result)

            assert yara_result is not None
            assert yara_result["label"] == "MALWARE"
            assert yara_result["score"] == 1.0


class TestEngineONNXFail:
    """ONNX falla → UNKNOWN/SUSPICIOUS."""

    def test_onnx_failure_suspicious(self, tmp_path):
        """Si ONNX falla, label debe ser UNKNOWN y operational_status SUSPICIOUS."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            # Mock extractor que retorna features
            engine.extractor = MagicMock()
            engine.extractor.extract.return_value = [0.0] * 2381
            engine.extractor.last_diagnostics = {}

            # Mock model que falla
            engine.model = MagicMock()
            engine.model.predict.side_effect = RuntimeError("ONNX session error")

            result = {
                "detection_phases": [],
                "details": {},
                "label": "Unknown",
                "score": -1.0,
                "operational_status": "UNKNOWN",
                "confidence": "Low",
                "status": "error",
            }

            engine._run_ml_phase(test_file, result)

            assert result["label"] == "UNKNOWN"
            assert result["score"] == -1.0
            assert result["operational_status"] == "SUSPICIOUS"


class TestEngineNonPEExe:
    """NonPEFileError en .exe → SUSPICIOUS."""

    def test_non_pe_exe_suspicious(self, tmp_path):
        """Archivo con extensión .exe pero no PE → operational_status SUSPICIOUS."""
        test_file = tmp_path / "fake.exe"
        test_file.write_text("not a PE file")

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            from core.errors import NonPEFileError
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            # Mock extractor que lanza NonPEFileError
            engine.extractor = MagicMock()
            engine.extractor.extract.side_effect = NonPEFileError(str(test_file))
            engine.extractor.last_diagnostics = {}
            engine.model = MagicMock()

            result = {
                "detection_phases": [],
                "details": {},
                "label": "Unknown",
                "score": -1.0,
                "operational_status": "UNKNOWN",
                "confidence": "Low",
                "status": "error",
            }

            engine._run_ml_phase(test_file, result)

            assert result["label"] == "NOT_PE"
            assert result["operational_status"] == "SUSPICIOUS"


class TestEngineBehavioralElevation:
    """Elevación de status por BehavioralShield."""

    def test_behavioral_elevation_dangerous(self, tmp_path):
        """risk_score >= 0.5 con status CLEAN → DANGEROUS."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            # Mock BehavioralShield con risk alto
            mock_shield = MagicMock()
            mock_report = MagicMock()
            mock_report.pid = 1234
            mock_report.process_name = "test.exe"
            mock_report.risk_score = 0.7
            mock_report.is_suspicious = True
            mock_report.suspicious_actions = []
            mock_report.scan_time_ms = 100
            mock_shield.analyze_process.return_value = mock_report
            engine._behavioral_shield = mock_shield

            # Mock _resolve_pid retorna un PID
            engine._resolve_pid = MagicMock(return_value=1234)

            result = {
                "detection_phases": [],
                "label": "BENIGN",
                "operational_status": "CLEAN",
                "behavioral_analysis": None,
            }

            engine._run_behavioral_phase(test_file, result)

            assert result["operational_status"] == "DANGEROUS"
            assert result["behavioral_analysis"] is not None

    def test_behavioral_elevation_suspicious(self, tmp_path):
        """risk_score >= 0.3 con status CLEAN → SUSPICIOUS."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            mock_shield = MagicMock()
            mock_report = MagicMock()
            mock_report.pid = 1234
            mock_report.process_name = "test.exe"
            mock_report.risk_score = 0.35
            mock_report.is_suspicious = False
            mock_report.suspicious_actions = []
            mock_report.scan_time_ms = 50
            mock_shield.analyze_process.return_value = mock_report
            engine._behavioral_shield = mock_shield
            engine._resolve_pid = MagicMock(return_value=1234)

            result = {
                "detection_phases": [],
                "label": "BENIGN",
                "operational_status": "CLEAN",
                "behavioral_analysis": None,
            }

            engine._run_behavioral_phase(test_file, result)

            assert result["operational_status"] == "SUSPICIOUS"


def test_yara_match_never_unknown(tmp_path):
    """T-03: YARA early-exit nunca produce operational_status=UNKNOWN."""
    test_file = tmp_path / "malware.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 200)
    with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
        from core.engine import ShadowNetEngine
        engine = ShadowNetEngine.__new__(ShadowNetEngine)
        mock_yara = MagicMock()
        mock_yara.is_available = True
        mock_scan = MagicMock()
        mock_scan.has_matches = True
        mock_scan.threat_names = ["Trojan.Test"]
        mock_scan.categories = ["trojan"]
        mock_scan.matches = [MagicMock(rule_name="Trojan_Test", category="trojan", tags=[])]
        mock_scan.scan_time_ms = 1.0
        mock_yara.scan.return_value = mock_scan
        engine._yara_scanner = mock_yara
        engine._behavioral_shield = None
        result = {"detection_phases": [], "yara_matches": [], "operational_status": "SUSPICIOUS"}
        yara_result = engine._run_yara_phase(test_file, result)
        assert yara_result is not None
        assert yara_result["operational_status"] != "UNKNOWN"
        assert yara_result["operational_status"] == "DANGEROUS"


class TestEnginePhaseFaultTolerance:
    """Fase falla → pipeline continúa sin propagar la excepción."""

    def test_phase_failure_continues(self, tmp_path):
        """Si _run_overlay_phase lanza excepción, el pipeline la captura y continúa."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            # Mocks mínimos para fases previas a overlay
            engine._yara_scanner = None
            engine._unpacker = None
            engine._behavioral_shield = None
            engine.extractor = MagicMock()
            engine.extractor.extract.return_value = [0.0] * 2381
            engine.extractor.last_diagnostics = {}
            engine.model = MagicMock()
            engine.model.predict.return_value = 0.2

            # Mockear las fases como métodos de instancia
            engine._run_yara_phase = MagicMock(return_value=None)
            engine._run_unpack_phase = MagicMock(return_value=test_file)
            engine._run_ml_phase = MagicMock()
            # _run_overlay_phase → FALLA (esto es lo que testamos)
            engine._run_overlay_phase = MagicMock(
                side_effect=RuntimeError("overlay crashed")
            )
            engine._run_dotnet_phase = MagicMock(
                side_effect=RuntimeError("dotnet crashed")
            )
            engine._run_il_phase = MagicMock()
            engine._run_behavioral_phase = MagicMock()

            # El pipeline NO debe propagar ninguna excepción
            result = engine._scan_file_internal(test_file)

            # Debe retornar un dict con 'label'
            assert isinstance(result, dict), "El resultado debe ser un dict"
            assert "label" in result, "El resultado debe tener campo 'label'"
            # El error de overlay debe estar registrado en details
            assert result.get("details", {}).get("overlay_phase_error") is True, \
                "overlay_phase_error debe ser True cuando la fase falla"
            assert result.get("details", {}).get("dotnet_phase_error") is True, \
                "dotnet_phase_error debe ser True cuando la fase falla"
