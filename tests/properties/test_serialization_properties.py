"""
tests/properties/test_serialization_properties.py — Tests de propiedades de serialización.

18.5 — Property 30 con Hypothesis.
"""
from __future__ import annotations

import sys
from pathlib import Path

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

from backend.app.schemas.dto import (
    ScanResult, ScanResultLabel, ScanType, RiskLevel, AnalysisType,
)

if HAS_HYPOTHESIS:

    _label_st = st.sampled_from(list(ScanResultLabel))
    _risk_st = st.sampled_from(list(RiskLevel))
    _scan_type_st = st.sampled_from(list(ScanType))
    _analysis_type_st = st.one_of(st.none(), st.sampled_from(list(AnalysisType)))

    _feature_list = st.lists(
        st.text(
            alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
            max_size=20,
        ),
        max_size=10,
    )

    _hex_str = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)

    _detection_phases = st.lists(
        st.sampled_from(["YARA", "UPX_DETECT", "UPX_UNPACK", "ML_STATIC", "IL_ANALYSIS", "BEHAVIORAL"]),
        max_size=6,
        unique=True,
    )

    @given(
        file_name=st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters="._-",
            ),
            min_size=1, max_size=60,
        ),
        result=_label_st,
        confidence=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        risk_level=_risk_st,
        scan_type=_scan_type_st,
        analysis_type=_analysis_type_st,
        features=_feature_list,
        was_unpacked=st.booleans(),
        is_dotnet=st.booleans(),
        sha256=st.one_of(st.none(), _hex_str),
        detection_phases=_detection_phases,
    )
    @settings(suppress_health_check=[HealthCheck.too_slow], max_examples=300)
    def test_prop30_scan_result_roundtrip(
        file_name, result, confidence, risk_level, scan_type,
        analysis_type, features, was_unpacked, is_dotnet,
        sha256, detection_phases,
    ):
        """Prop 30: ScanResult(**original.model_dump()) == campos del original."""
        original = ScanResult(
            file_name=file_name,
            result=result,
            confidence=confidence,
            scan_time="1.0s",
            risk_level=risk_level,
            scan_type=scan_type,
            analysis_type=analysis_type,
            features_detected=features,
            was_unpacked=was_unpacked,
            is_dotnet=is_dotnet,
            sha256=sha256,
            detection_phases=detection_phases,
        )

        dumped = original.model_dump()
        restored = ScanResult(**dumped)

        assert restored.file_name == original.file_name
        assert restored.result == original.result
        assert abs(restored.confidence - original.confidence) < 1e-9
        assert restored.risk_level == original.risk_level
        assert restored.scan_type == original.scan_type
        assert restored.was_unpacked == original.was_unpacked
        assert restored.is_dotnet == original.is_dotnet
        assert restored.sha256 == original.sha256
        assert set(restored.detection_phases) == set(original.detection_phases)

    @given(
        result=_label_st,
        risk_level=_risk_st,
        scan_type=_scan_type_st,
    )
    def test_prop30b_enums_serialize_as_strings(result, risk_level, scan_type):
        """Prop 30b: Enums serializados como string values planos."""
        sr = ScanResult(
            file_name="test.exe",
            result=result,
            confidence=0.5,
            scan_time="1s",
            risk_level=risk_level,
            scan_type=scan_type,
        )
        dumped = sr.model_dump()
        assert isinstance(dumped["result"], str)
        assert isinstance(dumped["risk_level"], str)
        assert isinstance(dumped["scan_type"], str)
        assert "." not in dumped["result"]
        assert "." not in dumped["risk_level"]
        assert "." not in dumped["scan_type"]

else:
    def test_prop30_scan_result_roundtrip(): pytest.skip("hypothesis no instalado")
    def test_prop30b_enums_serialize_as_strings(): pytest.skip("hypothesis no instalado")
