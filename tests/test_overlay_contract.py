"""
tests/test_overlay_contract.py — Paridad del contrato ShadowNetFeatures_v1.1.

Verifica que:
  1. El notebook de entrenamiento usa exactamente OVERLAY_FEATURE_NAMES
     en el mismo orden que core.overlay_features ( train == prod ).
  2. compute_overlay_features es determinista y correcta en casos conocidos:
     patron sample1.exe (stub + payload), PE sin overlay y vector degenerado.
Todo sintetico: sin descargas, sin SOREL, sin binarios.
"""
import json
from pathlib import Path

import numpy as np
import pytest

from core.overlay_features import (
    N_OVERLAY,
    OVERLAY_FEATURE_NAMES,
    compute_overlay_features,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TRAINING_NB = (
    REPO_ROOT / "Model_Collab" / "Kaggle-MLP-PE"
    / "shadow_net_sorel_7m_mlp_training.ipynb"
)

EXPECTED_NAMES = [
    "slack_ratio",
    "slack_bytes_log",
    "file_size_log",
    "imports_log",
    "has_cert",
    "stub_overlay_pattern",
]


def _notebook_names() -> list:
    nb = json.loads(TRAINING_NB.read_text(encoding="utf-8"))
    for cell in nb["cells"]:
        src = "".join(cell["source"]) if isinstance(cell["source"], list) else cell["source"]
        if "OVERLAY_FEATURE_NAMES =" in src:
            ns: dict = {}
            # Ejecuta solo la asignacion de la lista (sin imports ni red).
            start = src.index("OVERLAY_FEATURE_NAMES =")
            snippet = src[start:].splitlines()
            lines = [snippet[0]]
            for ln in snippet[1:]:
                lines.append(ln)
                if ln.strip().startswith("]"):
                    break
            exec("\n".join(lines), {}, ns)  # noqa: S102 (contenido propio del repo)
            return ns["OVERLAY_FEATURE_NAMES"]
    raise AssertionError("OVERLAY_FEATURE_NAMES no encontrado en el notebook")


def _vec(*, size=0.0, vsize=0.0, imports=0.0, cert=0.0) -> np.ndarray:
    v = np.zeros(2381, dtype=np.float32)
    v[616] = size
    v[617] = vsize
    v[620] = imports
    v[623] = cert
    return v


def test_contract_names_match_notebook():
    assert OVERLAY_FEATURE_NAMES == EXPECTED_NAMES
    assert N_OVERLAY == 6
    assert _notebook_names() == OVERLAY_FEATURE_NAMES


def test_sample1_pattern():
    # Caso documentado sample1.exe: stub ~0.3MB, total ~20.9MB, 3 imports, sin cert.
    v = _vec(size=20.9 * 1024 * 1024, vsize=0.3 * 1024 * 1024, imports=3, cert=0)
    o = compute_overlay_features(v)
    assert o.shape == (6,)
    assert 0.98 < o[0] < 0.99          # slack_ratio ~98.7%
    assert o[1] > 16.0                 # log1p(~19.7MB)
    assert o[4] == 0.0                 # sin cert
    assert o[5] == 1.0                 # patron stub+payload
    # Determinismo bit a bit.
    assert np.array_equal(o, compute_overlay_features(v.copy()))


def test_no_overlay():
    v = _vec(size=1.0 * 1024 * 1024, vsize=1.0 * 1024 * 1024, imports=50, cert=1)
    o = compute_overlay_features(v)
    assert o[0] == 0.0
    assert o[1] == 0.0
    assert o[4] == 1.0
    assert o[5] == 0.0


def test_degenerate_zeros():
    o = compute_overlay_features(np.zeros(2381, dtype=np.float32))
    assert np.all(o == 0.0)


def test_vsize_larger_than_size_clips():
    v = _vec(size=1000.0, vsize=5000.0, imports=10, cert=0)
    o = compute_overlay_features(v)
    assert o[0] == 0.0  # recorte conservador, nunca negativo
    assert o[5] == 0.0


def test_batch_shape_and_finiteness():
    rng = np.random.default_rng(7)
    X = rng.uniform(0, 1e7, size=(128, 2381)).astype(np.float32)
    O = compute_overlay_features(X)
    assert O.shape == (128, 6)
    assert O.dtype == np.float32
    assert np.all(np.isfinite(O))
    assert O[:, 0].min() >= 0.0 and O[:, 0].max() <= 1.0
    assert set(np.unique(O[:, 4])).issubset({0.0, 1.0})
    assert set(np.unique(O[:, 5])).issubset({0.0, 1.0})
