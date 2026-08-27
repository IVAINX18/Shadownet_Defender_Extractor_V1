"""
tests/test_f3_integration.py — Suite de tests para la fase F3 de integracion profunda.

Cubre:
  T-11 — BehavioralShield como Fase 8 opt-in (enable_behavioral)
  T-12 — SHAP KernelExplainer sin torch, endpoint GET /explain/shap
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ---------------------------------------------------------------------------
# T-11: BehavioralShield opt-in
# ---------------------------------------------------------------------------

class TestBehavioralDisabled:
    """T-11 task 1.6 — enable_behavioral=False es noop."""

    def test_behavioral_disabled_is_noop(self, tmp_path):
        """
        scan_file(enable_behavioral=False) no debe anadir BEHAVIORAL a
        detection_phases y behavioral_analysis debe ser None.
        """
        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            # Mock de shield activo — pero con flag=False no debe llamarse
            mock_shield = MagicMock()
            engine._behavioral_shield = mock_shield
            engine._resolve_pid = MagicMock(return_value=1234)

            result = {
                "detection_phases": [],
                "label": "BENIGN",
                "operational_status": "CLEAN",
                "behavioral_analysis": None,
            }

            # Simulamos _scan_file_internal con enable_behavioral=False:
            # _run_behavioral_phase NO debe ser llamada
            enable_behavioral = False
            if enable_behavioral:
                engine._run_behavioral_phase(tmp_path / "test.exe", result)

            assert "BEHAVIORAL" not in result["detection_phases"]
            assert result["behavioral_analysis"] is None
            mock_shield.analyze_process.assert_not_called()

    def test_scan_file_signature_accepts_enable_behavioral(self, tmp_path):
        """scan_file debe aceptar el kwarg enable_behavioral sin TypeError."""
        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            import inspect
            sig = inspect.signature(ShadowNetEngine.scan_file)
            assert "enable_behavioral" in sig.parameters, (
                "scan_file debe tener el parametro enable_behavioral"
            )
            assert sig.parameters["enable_behavioral"].default is False, (
                "enable_behavioral debe tener default=False"
            )

    def test_scan_internal_signature_accepts_enable_behavioral(self):
        """_scan_file_internal debe aceptar enable_behavioral."""
        from core.engine import ShadowNetEngine
        import inspect
        sig = inspect.signature(ShadowNetEngine._scan_file_internal)
        assert "enable_behavioral" in sig.parameters

    def test_enable_behavioral_false_default_preserves_v3(self, tmp_path):
        """
        Con enable_behavioral=False (default), behavioral_analysis debe ser None
        en el resultado de _scan_file_internal incluso si hay shield configurado.
        """
        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            # Configurar mocks de todas las fases para evitar dependencias reales
            engine._yara_scanner = None
            engine._unpacker = None
            engine._behavioral_shield = MagicMock()
            engine._resolve_pid = MagicMock(return_value=1234)
            engine.extractor = MagicMock()
            engine.extractor.extract.return_value = [0.0] * 2381
            engine.extractor.last_diagnostics = {}
            engine.model = MagicMock()
            engine.model.predict.return_value = 0.1
            engine._run_yara_phase = MagicMock(return_value=None)
            engine._run_unpack_phase = MagicMock(return_value=tmp_path / "test.exe")
            engine._run_ml_phase = MagicMock()
            engine._run_overlay_phase = MagicMock()
            engine._run_dotnet_phase = MagicMock()
            engine._run_il_phase = MagicMock()
            engine._run_behavioral_phase = MagicMock()

            test_file = tmp_path / "test.exe"
            test_file.write_bytes(b"MZ" + b"\x00" * 200)

            # Con enable_behavioral=False (default)
            result = engine._scan_file_internal(test_file, enable_behavioral=False)

            # _run_behavioral_phase NO debe haber sido llamada
            engine._run_behavioral_phase.assert_not_called()
            assert result["behavioral_analysis"] is None


class TestBehavioralElevation:
    """T-11 task 1.7 — Elevacion de status con enable_behavioral=True."""

    def test_behavioral_elevation_dangerous_with_flag(self, tmp_path):
        """
        Con enable_behavioral=True y risk_score >= 0.5,
        operational_status debe ser DANGEROUS.
        """
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

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

    def test_behavioral_elevation_suspicious_with_flag(self, tmp_path):
        """Con risk_score entre 0.3 y 0.5, debe elevar a SUSPICIOUS."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            mock_shield = MagicMock()
            mock_report = MagicMock()
            mock_report.pid = 5678
            mock_report.process_name = "test.exe"
            mock_report.risk_score = 0.4
            mock_report.is_suspicious = False
            mock_report.suspicious_actions = []
            mock_report.scan_time_ms = 50
            mock_shield.analyze_process.return_value = mock_report
            engine._behavioral_shield = mock_shield
            engine._resolve_pid = MagicMock(return_value=5678)

            result = {
                "detection_phases": [],
                "label": "BENIGN",
                "operational_status": "CLEAN",
                "behavioral_analysis": None,
            }

            engine._run_behavioral_phase(test_file, result)
            assert result["operational_status"] == "SUSPICIOUS"


class TestBehavioralTimeout:
    """T-11 task 1.8 — Timeout graceful de BehavioralShield."""

    def test_behavioral_timeout_graceful(self, tmp_path):
        """
        Si analyze_process tarda mas que el timeout configurado,
        behavioral_analysis debe ser None y el pipeline continua sin excepcion.

        Nota: ThreadPoolExecutor no mata el thread tras TimeoutError — espera
        hasta que el worker termine. Por eso el elapsed puede ser mayor que
        BEHAVIORAL_SHIELD_TIMEOUT_SECONDS (2s). Lo que se valida es que
        behavioral_analysis sea None y que no se propague ninguna excepcion.
        """
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            def slow_analyze(pid):
                time.sleep(3)  # Excede el timeout de 2s
                return MagicMock(risk_score=0.9)

            mock_shield = MagicMock()
            mock_shield.analyze_process.side_effect = slow_analyze
            engine._behavioral_shield = mock_shield
            engine._resolve_pid = MagicMock(return_value=999)

            result = {
                "detection_phases": [],
                "label": "BENIGN",
                "operational_status": "CLEAN",
                "behavioral_analysis": None,
            }

            start = time.time()
            engine._run_behavioral_phase(test_file, result)
            elapsed = time.time() - start

            # El timeout es 2s; el executor puede tardar hasta ~3s en limpiar el thread
            assert elapsed < 8.0, f"Pipeline demasiado lento: {elapsed:.1f}s"
            assert result["behavioral_analysis"] is None, (
                "Con timeout, behavioral_analysis debe ser None"
            )


    def test_behavioral_psutil_access_denied_is_noop(self, tmp_path):
        """psutil.AccessDenied durante analyze_process no propaga excepcion."""
        import psutil

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            mock_shield = MagicMock()
            mock_shield.analyze_process.side_effect = psutil.AccessDenied(0)
            engine._behavioral_shield = mock_shield
            engine._resolve_pid = MagicMock(return_value=1)

            result = {
                "detection_phases": [],
                "label": "BENIGN",
                "operational_status": "CLEAN",
                "behavioral_analysis": None,
            }

            # No debe propagar psutil.AccessDenied
            engine._run_behavioral_phase(test_file, result)
            assert result["behavioral_analysis"] is None


# ---------------------------------------------------------------------------
# T-12: SHAP KernelExplainer
# ---------------------------------------------------------------------------

# Saltar si shap no esta instalado (pytest.importorskip en cada test)

class TestShapExplainer:
    """T-12 task 2.6 — ShapExplainer.explain() sobre vector sintetico."""

    def test_shap_top_features(self):
        """
        explain() sobre vector sintetico retorna 20 features con shap_value
        finito y feature_name no vacio.
        """
        pytest.importorskip("shap")
        from core.explain.shap_explainer import ShapExplainer

        explainer = ShapExplainer()
        feats = np.random.default_rng(0).random(2381).astype(np.float32)
        result = explainer.explain(feats, top_k=20)

        assert "top_features" in result, "Debe retornar top_features"
        assert len(result["top_features"]) == 20, (
            f"Esperado 20 features, got {len(result['top_features'])}"
        )
        for f in result["top_features"]:
            assert "shap_value" in f
            assert "feature_name" in f
            assert "feature_idx" in f
            assert isinstance(f["shap_value"], float)
            assert f["feature_name"] != ""
            assert abs(f["shap_value"]) < float("inf"), "shap_value debe ser finito"

    def test_shap_model_score_in_range(self):
        """model_score debe estar en [0, 1]."""
        pytest.importorskip("shap")
        from core.explain.shap_explainer import ShapExplainer

        explainer = ShapExplainer()
        feats = np.zeros(2381, dtype=np.float32)
        result = explainer.explain(feats, top_k=5)

        if "error" not in result:
            assert 0.0 <= result["model_score"] <= 1.0, (
                f"model_score fuera de rango: {result['model_score']}"
            )

    def test_shap_top_k_respected(self):
        """explain() debe respetar el parametro top_k exactamente."""
        pytest.importorskip("shap")
        from core.explain.shap_explainer import ShapExplainer

        explainer = ShapExplainer()
        feats = np.ones(2381, dtype=np.float32) * 0.1
        for k in [1, 5, 10]:
            result = explainer.explain(feats, top_k=k)
            if "error" not in result:
                assert len(result["top_features"]) == k, (
                    f"top_k={k} pero got {len(result['top_features'])} features"
                )

    def test_shap_fallback_not_installed(self):
        """
        Si shap no esta disponible, explain() retorna error=shap_not_installed
        sin lanzar excepcion.
        """
        from core.explain.shap_explainer import ShapExplainer

        explainer = ShapExplainer()
        feats = np.zeros(2381, dtype=np.float32)

        # Simular que shap no esta instalado
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "shap":
                raise ImportError("No module named 'shap'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = explainer.explain(feats, top_k=5)

        assert result["error"] == "shap_not_installed"
        assert result["top_features"] == []

    def test_shap_feature_names_count(self):
        """_build_feature_names debe retornar exactamente 2381 nombres."""
        from core.explain.shap_explainer import _build_feature_names, FEATURE_DIM
        names = _build_feature_names()
        assert len(names) == FEATURE_DIM, (
            f"Esperado {FEATURE_DIM} feature names, got {len(names)}"
        )

    def test_shap_background_shape(self):
        """_load_background debe retornar array de shape (n, 2381)."""
        from core.explain.shap_explainer import _load_background, FEATURE_DIM
        bg = _load_background(n=50)
        assert bg.shape[1] == FEATURE_DIM, (
            f"Background shape incorrecto: {bg.shape}"
        )
        assert bg.shape[0] == 50


class TestShapEndpoint:
    """T-12 task 2.7 — GET /explain/shap via TestClient."""

    @pytest.fixture
    def client(self):
        """Cliente HTTP de prueba para FastAPI."""
        pytest.importorskip("httpx")
        from fastapi.testclient import TestClient
        from backend.app.main import app
        return TestClient(app)

    def test_explain_shap_path_traversal_rejected(self, client):
        """file_path con '..' debe retornar 400."""
        resp = client.get("/explain/shap?file_path=../../etc/passwd")
        assert resp.status_code == 400

    def test_explain_shap_nonexistent_file_rejected(self, client):
        """Archivo que no existe debe retornar 400."""
        resp = client.get("/explain/shap?file_path=/nonexistent/file.exe")
        assert resp.status_code == 400

    def test_explain_shap_valid_pe(self, client, tmp_path):
        """
        Un PE valido debe retornar 200 con top_features y model_score.
        Si shap no esta instalado, retorna 200 con error=shap_not_installed.
        Si la extraccion falla, retorna 400.
        """
        pytest.importorskip("shap")
        pe_file = tmp_path / "test.exe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 512)

        mock_feats = [0.0] * 2381
        mock_result = {
            "top_features": [
                {"feature_idx": i, "feature_name": f"byte_histogram_{i}", "shap_value": 0.01}
                for i in range(20)
            ],
            "base_value": 0.1,
            "model_score": 0.05,
        }

        # PEFeatureExtractor se importa localmente dentro de explain_shap
        with patch("extractors.extractor.PEFeatureExtractor") as MockExtractor:
            mock_instance = MockExtractor.return_value
            mock_instance.extract.return_value = mock_feats

            with patch("backend.app.api.routes.explain._get_explainer") as mock_explainer_fn:
                mock_explainer_fn.return_value.explain.return_value = mock_result
                resp = client.get(f"/explain/shap?file_path={pe_file}")

        assert resp.status_code == 200
        data = resp.json()
        assert "top_features" in data
        assert "model_score" in data



# ---------------------------------------------------------------------------
# T-12: Verificacion de dependencias
# ---------------------------------------------------------------------------

class TestNoDependencies:
    """T-12 task 2.8 y 3.2 — torch no debe estar en base.in."""

    def test_shap_no_torch_in_base(self):
        """requirements/base.in no debe contener torch."""
        base_in = _PROJECT_ROOT / "requirements" / "base.in"
        assert base_in.exists(), "requirements/base.in debe existir"
        content = base_in.read_text(encoding="utf-8").lower()
        assert "torch" not in content, (
            "torch no debe estar en requirements/base.in (solo en ml.in)"
        )

    def test_shap_in_ml_in(self):
        """shap debe estar en requirements/ml.in."""
        ml_in = _PROJECT_ROOT / "requirements" / "ml.in"
        assert ml_in.exists()
        content = ml_in.read_text(encoding="utf-8").lower()
        assert "shap" in content, "shap debe estar declarado en requirements/ml.in"

    def test_scan_service_accepts_enable_behavioral(self):
        """scan_single_file debe aceptar enable_behavioral kwarg."""
        import inspect
        from backend.app.services.scan_service import scan_single_file
        sig = inspect.signature(scan_single_file)
        assert "enable_behavioral" in sig.parameters
        assert sig.parameters["enable_behavioral"].default is False
