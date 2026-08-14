"""
tests/properties/test_n8n_properties.py — Tests de propiedades del N8N client.

18.4 — Properties 16, 17, 18 con Hypothesis.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from hypothesis import given, settings, HealthCheck
    from hypothesis import strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

pytestmark = pytest.mark.skipif(
    not HAS_HYPOTHESIS,
    reason="hypothesis no instalado (pip install hypothesis)",
)

from core.integrations.n8n_client import send_scan_result, _safe_json

if HAS_HYPOTHESIS:

    @given(
        result=st.sampled_from(["benign", "unknown", "", "clean", "safe"]),
        op_status=st.sampled_from(["CLEAN", "SUSPICIOUS", "UNKNOWN", "", "safe"]),
        filename=st.text(max_size=50),
        score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    )
    def test_prop16_non_alert_always_skip(result, op_status, filename, score):
        """Prop 16: result no-malicious y op_status no-DANGEROUS → siempre False."""
        r = send_scan_result({
            "result": result,
            "operational_status": op_status,
            "file_name": filename,
            "confidence": score,
        })
        assert r is False

    _primitive = st.one_of(
        st.none(), st.booleans(),
        st.integers(-10000, 10000),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(max_size=30),
    )
    _nested = st.recursive(
        _primitive,
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(st.text(max_size=10), children, max_size=5),
        ),
        max_leaves=15,
    )

    @given(payload=_nested)
    @settings(suppress_health_check=[HealthCheck.too_slow], max_examples=300)
    def test_prop17_safe_json_payload_serializable(payload):
        """Prop 17: _safe_json produce datos siempre json.dumps-able."""
        sanitized = _safe_json(payload)
        try:
            serialized = json.dumps(sanitized)
        except (ValueError, TypeError) as exc:
            assert False, f"_safe_json produjo JSON inválido: {exc}"
        assert "NaN" not in serialized
        assert "Infinity" not in serialized

    @given(
        result=st.sampled_from(["malicious", "suspicious", "benign", "unknown"]),
        op_status=st.sampled_from(["DANGEROUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"]),
    )
    def test_prop18_disabled_always_false(result, op_status):
        """Prop 18: N8N_ENABLED=False → siempre False."""
        with patch.dict(os.environ, {"N8N_ENABLED": "false"}, clear=False):
            r = send_scan_result({
                "result": result,
                "operational_status": op_status,
                "file_name": "test.exe",
                "confidence": 0.9,
            })
        assert r is False

else:
    def test_prop16_non_alert_always_skip(): pytest.skip("hypothesis no instalado")
    def test_prop17_safe_json_payload_serializable(): pytest.skip("hypothesis no instalado")
    def test_prop18_disabled_always_false(): pytest.skip("hypothesis no instalado")
