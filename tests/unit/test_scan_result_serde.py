"""
tests/unit/test_scan_result_serde.py — Round-trip serialización ScanResult.

17.3 — Cubre:
  - Serialización/deserialización de ScanResult preserva todos los campos
  - Enums se serializan como valores string planos
  - Campos opcionales pueden ser None
"""
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.schemas.dto import (
    ScanResult,
    ScanResultLabel,
    ScanType,
    RiskLevel,
    AnalysisType,
)


class TestScanResultSerde:
    """Round-trip serialización ScanResult."""

    def test_roundtrip_full(self):
        """ScanResult con todos los campos → model_dump → ScanResult."""
        original = ScanResult(
            file_name="test_malware.exe",
            scan_type=ScanType.SINGLE,
            result=ScanResultLabel.MALICIOUS,
            confidence=0.95,
            scan_time="2.34s",
            features_detected=["packed", "anti_debug"],
            risk_level=RiskLevel.HIGH,
            analysis_type=AnalysisType.PE,
            user_id="user-123",
            user_email="test@example.com",
            yara_matches=[{"rule": "Trojan.Test", "meta": {}}],
            was_unpacked=True,
            detection_phases=["YARA", "UPX_UNPACK", "ML_STATIC"],
            is_dotnet=False,
            sha256="a" * 64,
            behavioral_analysis={"pid": 123, "risk_score": 0.8},
        )

        dumped = original.model_dump()
        restored = ScanResult(**dumped)

        assert restored.file_name == "test_malware.exe"
        assert restored.result == "malicious"
        assert restored.confidence == 0.95
        assert restored.scan_type == "single"
        assert restored.risk_level == "high"
        assert restored.sha256 == "a" * 64
        assert restored.was_unpacked is True
        assert len(restored.detection_phases) == 3
        assert restored.behavioral_analysis is not None

    def test_enum_serialization_as_string(self):
        """Enums se serializan como valores string, no como representación enum."""
        result = ScanResult(
            file_name="test.exe",
            result=ScanResultLabel.SUSPICIOUS,
            confidence=0.5,
            scan_time="1s",
            risk_level=RiskLevel.MEDIUM,
        )

        dumped = result.model_dump()
        assert dumped["result"] == "suspicious"
        assert dumped["risk_level"] == "medium"
        assert dumped["scan_type"] == "single"

    def test_optional_fields_none(self):
        """Campos opcionales como None deben persistir correctamente."""
        result = ScanResult(
            file_name="test.exe",
            result=ScanResultLabel.BENIGN,
            confidence=0.1,
            scan_time="0.5s",
            risk_level=RiskLevel.LOW,
            explanation=None,
            sha256=None,
            behavioral_analysis=None,
        )

        dumped = result.model_dump()
        assert dumped["explanation"] is None
        assert dumped["sha256"] is None
        assert dumped["behavioral_analysis"] is None

        restored = ScanResult(**dumped)
        assert restored.explanation is None
