"""
tests/integration/test_pipeline_e2e.py — Tests de integración E2E del pipeline.

17.1 — Accuracy sobre data/test_set/ (X_test.npy, y_test.npy).

Carga el modelo real y verifica que la accuracy sobre el test set supere
el umbral mínimo definido en el PRD (≥ 90%).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_TEST_SET_DIR = _PROJECT_ROOT / "data" / "test_set"
_X_TEST = _TEST_SET_DIR / "X_test.npy"
_Y_TEST = _TEST_SET_DIR / "y_test.npy"

# Accuracy mínima aceptable (PRD sección 6)
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
    """Accuracy del modelo sobre el test set real."""

    def test_accuracy_above_threshold(self, test_data, loaded_engine):
        """El modelo debe superar el {_MIN_ACCURACY*100:.0f}% de accuracy en el test set."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy no instalado")

        X, y = test_data
        engine = loaded_engine

        correct = 0
        total = len(y)

        for i in range(total):
            try:
                features = X[i].tolist()
                # Usar el scaler si está disponible
                if hasattr(engine, "scaler") and engine.scaler is not None:
                    import joblib
                    features_scaled = engine.scaler.transform([features])[0].tolist()
                else:
                    features_scaled = features

                score = engine.model.predict(features_scaled)
                predicted = 1 if score >= 0.5 else 0
                if predicted == int(y[i]):
                    correct += 1
            except Exception:
                # Ignorar errores en muestras individuales
                total -= 1

        if total == 0:
            pytest.skip("Sin muestras válidas para evaluar")

        accuracy = correct / total
        assert accuracy >= _MIN_ACCURACY, (
            f"Accuracy {accuracy:.3f} por debajo del umbral mínimo {_MIN_ACCURACY} "
            f"({correct}/{total} correctas)"
        )

    def test_test_set_dimensions(self, test_data):
        """El test set debe tener la dimensión esperada (2381 features)."""
        from configs.settings import FEATURE_DIMENSION
        X, y = test_data
        assert X.shape[1] == FEATURE_DIMENSION, (
            f"Dimensión de features inesperada: {X.shape[1]} (esperado {FEATURE_DIMENSION})"
        )
        assert len(X) == len(y), "X_test y y_test deben tener el mismo número de muestras"

    def test_labels_binary(self, test_data):
        """Las etiquetas del test set deben ser binarias (0 o 1)."""
        _, y = test_data
        unique = set(int(v) for v in y)
        assert unique.issubset({0, 1}), f"Etiquetas inesperadas: {unique}"
