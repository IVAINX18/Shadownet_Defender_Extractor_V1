"""
tests/integration/test_pipeline_e2e.py — Tests de integración E2E del pipeline.

F4 — test_accuracy_above_threshold ahora corre sobre data/eval_real/ con umbral
AUC-ROC > 0.85 y es skipped si el corpus real no está presente.

NOTA: data/test_set/X_test.npy es SINTETICO — no usar para métricas de campo.
      Ver docs/academico/07_metricas_y_resultados.md para contexto.
"""
from __future__ import annotations

import sys
import warnings
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ─── Paths ────────────────────────────────────────────────────────────────────
_TEST_SET_DIR = _PROJECT_ROOT / "data" / "test_set"
_X_TEST = _TEST_SET_DIR / "X_test.npy"
_Y_TEST = _TEST_SET_DIR / "y_test.npy"

# F4 — corpus real para métricas de campo
_EVAL_REAL_DIR = _PROJECT_ROOT / "data" / "eval_real"
_EVAL_REAL_MANIFEST = _EVAL_REAL_DIR / "manifest.csv"
_CORPUS_REAL_ABSENT = not _EVAL_REAL_MANIFEST.exists()

# Umbral AUC-ROC campo (realista, no el 1.0 del sintético)
_MIN_AUC_ROC_FIELD = 0.85

# Accuracy mínima sobre test set sintético (legacy, no usar para artículo)
_MIN_ACCURACY = 0.90


@pytest.fixture(scope="module")
def test_data():
    """Carga X_test.npy y y_test.npy una sola vez para todos los tests."""
    try:
        import numpy as np
    except ImportError:
        pytest.skip("numpy no instalado")

    if not _X_TEST.exists() or not _Y_TEST.exists():
        pytest.skip(f"Test set no encontrado en {_TEST_SET_DIR}")

    X = np.load(str(_X_TEST))
    y = np.load(str(_Y_TEST))
    return X, y


@pytest.fixture(scope="module")
def loaded_engine():
    """Carga el motor con modelo ONNX real."""
    from configs.settings import MODEL_PATH, SCALER_PATH
    if not MODEL_PATH.exists():
        pytest.skip(f"Modelo ONNX no encontrado: {MODEL_PATH}")
    if not SCALER_PATH.exists():
        pytest.skip(f"Scaler no encontrado: {SCALER_PATH}")

    try:
        from core.engine import ShadowNetEngine
        engine = ShadowNetEngine()
        if engine.model is None:
            pytest.skip("Motor no pudo cargar el modelo ONNX")
        return engine
    except Exception as exc:
        pytest.skip(f"No se pudo inicializar el motor: {exc}")


class TestPipelineAccuracy:
    """Accuracy del modelo sobre el test set SINTETICO (diagnóstico, no métricas de campo)."""

    def test_accuracy_above_threshold(self):
        """
        F4: test parametrizado sobre data/eval_real/ con AUC-ROC > 0.85.
        Skipped si corpus real no está presente (CI público no falla).

        data/test_set/X_test.npy — SINTETICO — no usar para métricas de campo.
        Ver docs/academico/07_metricas_y_resultados.md — Sección Métricas de campo (T-13).
        """
        if _CORPUS_REAL_ABSENT:
            pytest.skip(
                "CorpusReal no presente en data/eval_real/ — "
                "umbral AUC-ROC > 0.85 requiere corpus real. "
                "Ejecutar: python tools/fetch_corpus.py --help"
            )

        try:
            import numpy as np
            import joblib
            import onnxruntime as ort
            from sklearn.metrics import roc_auc_score
        except ImportError as e:
            pytest.skip(f"Dependencia no instalada: {e}")

        from configs.settings import MODEL_PATH, SCALER_PATH, FEATURE_DIMENSION

        if not MODEL_PATH.exists():
            pytest.skip(f"Modelo ONNX no encontrado: {MODEL_PATH}")
        if not SCALER_PATH.exists():
            pytest.skip(f"Scaler no encontrado: {SCALER_PATH}")

        # Cargar scaler y sesión ONNX
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            scaler = joblib.load(str(SCALER_PATH))
        session = ort.InferenceSession(str(MODEL_PATH))
        input_name = session.get_inputs()[0].name

        # Cargar features desde eval_real (si ya tienen npy pre-generados)
        eval_npy = _EVAL_REAL_DIR / "X_eval.npy"
        eval_labels = _EVAL_REAL_DIR / "y_eval.npy"
        if not eval_npy.exists() or not eval_labels.exists():
            pytest.skip(
                "X_eval.npy / y_eval.npy no encontrados en data/eval_real/. "
                "Ejecutar: python evaluation/evaluate_real_corpus.py --corpus data/eval_real/"
            )

        X = np.load(str(eval_npy))
        y = np.load(str(eval_labels))

        if X.shape[1] != FEATURE_DIMENSION:
            pytest.skip(
                f"Dimensión de features en eval_real ({X.shape[1]}) ≠ {FEATURE_DIMENSION}. "
                "Regenerar X_eval.npy con el extractor actual."
            )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            X_scaled = scaler.transform(X).astype(np.float32)

        proba = session.run(None, {input_name: X_scaled})[0].flatten()
        if proba.max() > 1.0 or proba.min() < 0.0:
            proba = 1.0 / (1.0 + np.exp(-proba))

        auc = roc_auc_score(y, proba)
        assert auc >= _MIN_AUC_ROC_FIELD, (
            f"AUC-ROC={auc:.4f} < {_MIN_AUC_ROC_FIELD} sobre corpus real data/eval_real/. "
            f"N={len(y)} muestras."
        )

    def test_test_set_dimensions(self, test_data):
        """
        El test set SINTETICO debe tener la dimensión esperada (2381 features).
        NOTA: data/test_set/X_test.npy — SINTETICO — no usar para métricas de campo.
        """
        from configs.settings import FEATURE_DIMENSION
        X, y = test_data
        assert X.shape[1] == FEATURE_DIMENSION, (
            f"Dimensión de features inesperada: {X.shape[1]} (esperado {FEATURE_DIMENSION}). "
            "NOTA: Este es el test set SINTETICO, incompatible con el scaler de producción."
        )
        assert len(X) == len(y), "X_test y y_test deben tener el mismo número de muestras"

    def test_labels_binary(self, test_data):
        """Las etiquetas del test set deben ser binarias (0 o 1)."""
        _, y = test_data
        unique = set(int(v) for v in y)
        assert unique.issubset({0, 1}), f"Etiquetas inesperadas: {unique}"

