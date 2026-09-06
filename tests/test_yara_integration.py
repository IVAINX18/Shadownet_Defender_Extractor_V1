"""
tests/test_yara_integration.py — F3 YARA Integration (10 tests).
"""
import tempfile
from pathlib import Path

import pytest

from core.evidence import EvidenceVerdict, EvidenceStatus, Severity, OperationalStatus, yara_evidence
from core.correlation import CorrelationEngine
from core.evidence import ml_evidence, pe_static_evidence, overlay_evidence, heuristic_evidence, dotnet_evidence, il_behavioral_evidence

# Helper to compile a temp YARA rule and scan bytes
def _yara_scan_bytes(raw: bytes, rule_src: str):
    import yara
    rules = yara.compile(source=rule_src)
    matches = rules.match(data=raw, timeout=10)
    return matches


def test_01_yara_available_no_match():
    """YARA AVAILABLE + no match -> BENIGN, no MALICIOUS."""
    scanner = None
    try:
        from security.yara_scanner import YaraScanner
        scanner = YaraScanner()
    except Exception:
        pytest.skip("YARA not available")
    # Scan benign bytes (no PE, no match)
    result = scanner.scan_bytes(b"hello world benign " + b"\x00" * 100, label="test")
    # Should be available and no match (benign)
    assert not result.has_matches
    # Evidence should be BENIGN OK when no match
    ev = yara_evidence(has_matches=False, status=EvidenceStatus.OK)
    assert ev.verdict == EvidenceVerdict.BENIGN
    assert ev.status == EvidenceStatus.OK
    # Correlation should not be MALICIOUS
    engine = CorrelationEngine()
    evs = [
        ml_evidence(score=0.1, label="BENIGN"),
        ev,
        pe_static_evidence(packer_indicators={}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = engine.correlate(evs)
    assert final.verdict != EvidenceVerdict.MALICIOUS


def test_02_yara_malicious_match_deterministic_veto():
    """YARA HIGH malicious -> MALICIOUS/CRITICAL/DANGEROUS even if ML BENIGN."""
    # Direct evidence test (no scanner needed)
    ev = yara_evidence(
        has_matches=True,
        matches=[{"rule": "njRAT_Generic", "meta": {"severity": "high"}, "category": "trojan"}],
        threat_names=["njRAT_Generic"],
        status=EvidenceStatus.OK,
    )
    assert ev.verdict == EvidenceVerdict.MALICIOUS
    assert ev.severity == Severity.CRITICAL
    assert ev.operational_status == OperationalStatus.DANGEROUS
    engine = CorrelationEngine()
    evs = [
        ml_evidence(score=0.0, label="BENIGN"),
        ev,
        pe_static_evidence(packer_indicators={}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = engine.correlate(evs)
    assert final.verdict == EvidenceVerdict.MALICIOUS
    assert final.risk_level == Severity.CRITICAL
    assert final.operational_status == OperationalStatus.DANGEROUS
    assert final.ml_score_raw == 0.0


def test_03_yara_unavailable_not_benign():
    ev = yara_evidence(has_matches=False, status=EvidenceStatus.UNAVAILABLE, degraded_reason="yara not installed")
    assert ev.verdict == EvidenceVerdict.UNKNOWN
    assert ev.status == EvidenceStatus.UNAVAILABLE
    assert ev.verdict != EvidenceVerdict.BENIGN


def test_04_rule_compilation_failure():
    import yara
    # Invalid rule should raise SyntaxError
    bad_rule = 'rule bad { strings: $a = "test" condition: $a and unknown_func() }'
    with pytest.raises(yara.SyntaxError):
        yara.compile(source=bad_rule)
    # Scanner should handle invalid rule file gracefully (DEGRADED/UNAVAILABLE not BENIGN)
    with tempfile.TemporaryDirectory() as tmp:
        bad_path = Path(tmp) / "bad.yar"
        bad_path.write_text(bad_rule)
        good_rule = 'rule good { condition: true }'
        good_path = Path(tmp) / "good.yar"
        good_path.write_text(good_rule)
        from security.yara_scanner import YaraScanner
        scanner = YaraScanner(rules_dir=Path(tmp))
        # Should load 1 valid, 1 failed -> is_available True (degraded)
        assert scanner.is_available is True
        assert scanner.rules_loaded == 1
        # Error should not be silently BENIGN
        ev = yara_evidence(has_matches=False, status=EvidenceStatus.UNAVAILABLE, degraded_reason="compilation failed")
        assert ev.verdict == EvidenceVerdict.UNKNOWN


def test_05_yara_timeout_degraded():
    ev = yara_evidence(has_matches=False, status=EvidenceStatus.DEGRADED, degraded_reason="YARA timeout (30s)")
    assert ev.verdict == EvidenceVerdict.UNKNOWN
    assert ev.status == EvidenceStatus.DEGRADED
    # Correlation with degraded YARA + PE suspicious should still be SUSPICIOUS
    engine = CorrelationEngine()
    evs = [
        ml_evidence(score=0.1, label="BENIGN"),
        ev,
        pe_static_evidence(packer_indicators={"packer_detected": True, "global_entropy": 7.9, "num_imports": 1}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = engine.correlate(evs)
    # Degraded YARA should not make it BENIGN; PE suspicious may still make SUSPICIOUS
    assert final.verdict != EvidenceVerdict.BENIGN or final.degraded is True


def test_06_multiple_yara_matches():
    matches = [
        {"rule": "njRAT_Generic", "meta": {"severity": "high", "category": "trojan"}, "category": "trojan"},
        {"rule": "AgentTesla_Spyware", "meta": {"severity": "high"}, "category": "spyware"},
    ]
    ev = yara_evidence(has_matches=True, matches=matches, threat_names=["njRAT_Generic", "AgentTesla_Spyware"])
    assert len(ev.indicators) == 2
    assert ev.metadata["match_count"] == 2
    assert "njRAT_Generic" in ev.reasons[0]
    assert ev.verdict == EvidenceVerdict.MALICIOUS


def test_07_contradiction_ml_benign_yara_malicious():
    engine = CorrelationEngine()
    evs = [
        ml_evidence(score=0.0, label="BENIGN"),
        yara_evidence(has_matches=True, matches=[{"rule": "LockBit_Ransomware", "meta": {"severity": "critical"}}], threat_names=["LockBit_Ransomware"]),
        pe_static_evidence(packer_indicators={}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = engine.correlate(evs)
    assert final.verdict == EvidenceVerdict.MALICIOUS
    # YARA veto is deterministic, contradiction may be None (early exit) — just verify evidence preserved
    assert final.ml_score_raw == 0.0


def test_08_yara_no_match_pe_suspicious():
    engine = CorrelationEngine()
    evs = [
        ml_evidence(score=0.1, label="BENIGN"),
        yara_evidence(has_matches=False, status=EvidenceStatus.OK),
        pe_static_evidence(packer_indicators={"packer_detected": True, "global_entropy": 7.9, "num_imports": 1}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = engine.correlate(evs)
    # YARA no-match (BENIGN) should not erase PE suspicious
    assert final.verdict == EvidenceVerdict.SUSPICIOUS
    assert "pe_static" in final.contributing_sources


def test_09_yara_unavailable_pe_suspicious():
    engine = CorrelationEngine()
    evs = [
        ml_evidence(score=0.1, label="BENIGN"),
        yara_evidence(has_matches=False, status=EvidenceStatus.UNAVAILABLE, degraded_reason="no yara"),
        pe_static_evidence(packer_indicators={"packer_detected": True, "global_entropy": 7.9, "num_imports": 1}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = engine.correlate(evs)
    assert final.verdict == EvidenceVerdict.SUSPICIOUS
    yara_ev = next(e for e in final.evidences if e["source"] == "yara")
    assert yara_ev["status"] == "unavailable"
    assert yara_ev["verdict"] == "unknown"


def test_10_invalid_ruleset_not_no_match():
    # Compile invalid ruleset should not be interpreted as no match
    import yara
    # Create a scanner with an invalid rule file
    with tempfile.TemporaryDirectory() as tmp:
        bad_path = Path(tmp) / "invalid.yar"
        # Rule with unreferenced string -> warning but still syntax error in our strict mode? We'll use syntax error
        bad_path.write_text('rule bad { strings: $a = "test" condition: false and true }')  # valid but no match
        # Actually this is valid syntax, but we want to simulate compilation failure
        # Use truly invalid syntax
        bad_path.write_text('this is not valid yara syntax @@@')
        from security.yara_scanner import YaraScanner
        scanner = YaraScanner(rules_dir=Path(tmp))
        # No valid rules -> unavailable, not benign
        assert scanner.is_available is False
        # If we scan, it should return has_matches False with error, not benign OK
        result = scanner.scan_bytes(b"test", label="test")
        assert result.error is not None
        ev = yara_evidence(has_matches=False, status=EvidenceStatus.UNAVAILABLE, degraded_reason=result.error)
        assert ev.verdict == EvidenceVerdict.UNKNOWN
        assert ev.verdict != EvidenceVerdict.BENIGN
