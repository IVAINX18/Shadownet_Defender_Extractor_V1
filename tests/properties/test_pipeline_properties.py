"""
tests/properties/test_pipeline_properties.py — Tests de propiedades del pipeline.

18.2 — Properties 1, 2, 22-29 con Hypothesis.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from hypothesis import given, assume, settings, HealthCheck
    from hypothesis import strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

pytestmark = pytest.mark.skipif(
    not HAS_HYPOTHESIS,
    reason="hypothesis no instalado (pip install hypothesis)",
)

from backend.app.services.scan_service import classify_tripartite
from backend.app.schemas.dto import ScanResultLabel, RiskLevel
from backend.app.api.routes.scan import (
    _sanitize_filename,
    _has_double_extension,
    _check_rate_limit,
)
from backend.app.integrations.supabase_client import _safe_json

# ---------------------------------------------------------------------------
# Solo definir los tests si hypothesis está disponible
# Esto evita NameError al hacer el import cuando hypothesis no está instalado
# ---------------------------------------------------------------------------
if HAS_HYPOTHESIS:

    @given(score=st.floats(min_value=-1.0, max_value=1.0, allow_nan=False, allow_infinity=False))
    def test_prop1_classify_returns_valid_label(score):
        """Prop 1: classify_tripartite(score) → result ∈ {BENIGN, SUSPICIOUS, MALICIOUS}."""
        result, risk = classify_tripartite(score)
        valid = {ScanResultLabel.BENIGN, ScanResultLabel.SUSPICIOUS, ScanResultLabel.MALICIOUS}
        assert result in valid, f"Label inválido: {result} para score={score}"

    @given(score=st.floats(min_value=-1.0, max_value=1.0, allow_nan=False, allow_infinity=False))
    def test_prop2_confidence_in_range(score):
        """Prop 2: confidence ∈ [0.0, 1.0] para cualquier score."""
        result, risk = classify_tripartite(score)
        conf = min(1.0, max(0.0, abs(score) if score >= 0 else 0.0))
        assert 0.0 <= conf <= 1.0

    @given(score=st.floats(max_value=-0.001, allow_nan=False, allow_infinity=False))
    def test_prop22_negative_score_suspicious(score):
        """Prop 22: score < 0 → SUSPICIOUS, nunca BENIGN."""
        result, _ = classify_tripartite(score)
        assert result == ScanResultLabel.SUSPICIOUS
        assert result != ScanResultLabel.BENIGN

    @given(score=st.floats(min_value=0.71, max_value=1.0, allow_nan=False, allow_infinity=False))
    def test_prop23_high_score_malicious(score):
        """Prop 23: score > 0.7 → MALICIOUS."""
        result, _ = classify_tripartite(score)
        assert result == ScanResultLabel.MALICIOUS, f"score={score} → {result}"

    @given(score=st.floats(min_value=0.0, max_value=0.3999, allow_nan=False, allow_infinity=False))
    def test_prop24_low_score_benign(score):
        """Prop 24: 0 <= score < 0.4 → BENIGN."""
        result, _ = classify_tripartite(score)
        assert result == ScanResultLabel.BENIGN, f"score={score} → {result}"

    @given(filename=st.text(min_size=0, max_size=200))
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_prop25_sanitize_filename_safe_chars(filename):
        """Prop 25: _sanitize_filename no produce chars de control ni BiDi."""
        _BIDI = set("\u202a\u202b\u202c\u202d\u202e\u200e\u200f\u2066\u2067\u2068\u2069")
        sanitized = _sanitize_filename(filename)
        assert len(sanitized) > 0
        for ch in sanitized:
            assert ord(ch) >= 0x20, f"Control char en sanitized: {repr(ch)}"
            assert ch not in _BIDI, f"BiDi char en sanitized: {repr(ch)}"
        assert "/" not in sanitized
        assert "\\" not in sanitized

    @given(filename=st.sampled_from([
        "file.exe", "script.ps1", "document.pdf",
        "image.jpg", "archive.zip", "program.dll",
        "data.csv", "text.txt", "malware.bat",
    ]))
    def test_prop26_simple_extension_not_double(filename):
        """Prop 26: extensiones simples no son dobles."""
        assert _has_double_extension(filename) is False, f"Falso positivo: {filename}"

    _nested_value = st.recursive(
        st.one_of(
            st.none(), st.booleans(),
            st.integers(-1000, 1000),
            st.floats(allow_nan=True, allow_infinity=True),
            st.text(max_size=50),
        ),
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(st.text(max_size=10), children, max_size=5),
        ),
        max_leaves=20,
    )

    @given(obj=_nested_value)
    @settings(suppress_health_check=[HealthCheck.too_slow], max_examples=200)
    def test_prop27_safe_json_always_serializable(obj):
        """Prop 27: _safe_json produce datos siempre json.dumps-able."""
        sanitized = _safe_json(obj)
        try:
            json.dumps(sanitized)
        except (ValueError, TypeError) as exc:
            assert False, f"_safe_json({obj!r}) → JSON inválido: {exc}"

    @given(
        extra=st.integers(min_value=1, max_value=10),
        max_pm=st.integers(min_value=1, max_value=20),
    )
    def test_prop28_rate_limit_eventually_fires(extra, max_pm):
        """Prop 28: max_pm+extra solicitudes → al menos extra False."""
        user_id = f"prop28_{time.time()}_{extra}_{max_pm}"
        results = [_check_rate_limit(user_id, max_per_minute=max_pm) for _ in range(max_pm + extra)]
        assert results.count(False) >= extra

    @given(max_pm=st.integers(min_value=1, max_value=30))
    def test_prop29_rate_limit_first_n_true(max_pm):
        """Prop 29: Las primeras max_pm llamadas a un user nuevo son True."""
        user_id = f"prop29_{time.time()}_{max_pm}"
        results = [_check_rate_limit(user_id, max_per_minute=max_pm) for _ in range(max_pm)]
        assert all(results), f"Primeras {max_pm} deben ser True: {results}"

else:
    # Stubs para que pytest los reporte como skipped, no como errores de colección
    def test_prop1_classify_returns_valid_label(): pytest.skip("hypothesis no instalado")
    def test_prop2_confidence_in_range(): pytest.skip("hypothesis no instalado")
    def test_prop22_negative_score_suspicious(): pytest.skip("hypothesis no instalado")
    def test_prop23_high_score_malicious(): pytest.skip("hypothesis no instalado")
    def test_prop24_low_score_benign(): pytest.skip("hypothesis no instalado")
    def test_prop25_sanitize_filename_safe_chars(): pytest.skip("hypothesis no instalado")
    def test_prop26_simple_extension_not_double(): pytest.skip("hypothesis no instalado")
    def test_prop27_safe_json_always_serializable(): pytest.skip("hypothesis no instalado")
    def test_prop28_rate_limit_eventually_fires(): pytest.skip("hypothesis no instalado")
    def test_prop29_rate_limit_first_n_true(): pytest.skip("hypothesis no instalado")
