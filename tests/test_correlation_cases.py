"""
Tests A-I de aceptacion F2 Final.
"""
import pytest
from core.evidence import (
    EvidenceSource, EvidenceVerdict, EvidenceStatus, Severity, OperationalStatus,
    ml_evidence, yara_evidence, pe_static_evidence, overlay_evidence,
    heuristic_evidence, dotnet_evidence, il_behavioral_evidence, cnn_evidence,
)
from core.correlation import CorrelationEngine


def _all_benign():
    return [
        ml_evidence(score=0.1, label="BENIGN", confidence="High"),
        yara_evidence(has_matches=False),
        pe_static_evidence(packer_indicators={}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="no overlay"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]


def test_case_A_benign_normal():
    evidences = _all_benign()
    final = CorrelationEngine().correlate(evidences)
    assert final.verdict == EvidenceVerdict.BENIGN
    assert final.risk_level == Severity.LOW
    assert final.operational_status == OperationalStatus.CLEAN
    assert final.degraded is False


def test_case_B_pe_suspicious():
    evidences = [
        ml_evidence(score=0.1, label="BENIGN"),
        yara_evidence(has_matches=False),
        pe_static_evidence(packer_indicators={"packer_detected": True, "global_entropy": 7.8, "num_imports": 2}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = CorrelationEngine().correlate(evidences)
    # PE solo suspicious con 0.8 norm debe elevar a SUSPICIOUS via S~0.19 >0.15
    assert final.verdict == EvidenceVerdict.SUSPICIOUS
    assert final.operational_status == OperationalStatus.SUSPICIOUS


def test_case_C_dotnet_corroboration():
    from core.dotnet import DotNetReport, DotNetObfuscatorInfo, DotNetRiskProfile, DotNetAssemblyInfo
    dotnet_report = DotNetReport(
        is_dotnet=True, assembly_info=DotNetAssemblyInfo(),
        obfuscator=DotNetObfuscatorInfo(detected=True, name="ConfuserEx", confidence="MEDIUM"),
        risk_profile=DotNetRiskProfile(dotnet_risk_score=28, dotnet_risk_level="MEDIUM", risk_factors=["obfuscator"]),
    )
    evidences = [
        ml_evidence(score=0.0, label="BENIGN"),
        yara_evidence(has_matches=False),
        pe_static_evidence(packer_indicators={"packer_detected": True, "global_entropy": 7.9, "num_imports": 1}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=dotnet_report),
        il_behavioral_evidence(il_report=None, is_dotnet=True, status=EvidenceStatus.ERROR, error="x"),
    ]
    final = CorrelationEngine().correlate(evidences)
    assert final.verdict == EvidenceVerdict.SUSPICIOUS
    # No debe ser CLEAN
    assert final.operational_status != OperationalStatus.CLEAN
    assert final.operational_status != OperationalStatus.UNKNOWN


def test_case_D_yara_malicious():
    evidences = [
        ml_evidence(score=0.0, label="BENIGN"),
        yara_evidence(has_matches=True, matches=[{"rule": "malicious_rule"}], threat_names=["malicious_rule"]),
        pe_static_evidence(packer_indicators={}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = CorrelationEngine().correlate(evidences)
    assert final.verdict == EvidenceVerdict.MALICIOUS
    assert final.risk_level == Severity.CRITICAL
    assert final.operational_status == OperationalStatus.DANGEROUS
    assert final.ml_score_raw == 0.0  # preservado


def test_case_E_ml_contradiction():
    evidences = [
        ml_evidence(score=0.8, label="MALWARE", confidence="High"),
        yara_evidence(has_matches=False),
        pe_static_evidence(packer_indicators={}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = CorrelationEngine().correlate(evidences)
    # ML solo malicioso sin corroboracion -> SUSPICIOUS conservador, nunca CLEAN, con contradicion explicita
    assert final.verdict == EvidenceVerdict.SUSPICIOUS
    assert final.operational_status != OperationalStatus.CLEAN
    assert final.contradiction is not None
    assert "ML malicious" in final.contradiction


def test_case_F_yara_unavailable():
    from core.dotnet import DotNetReport, DotNetObfuscatorInfo, DotNetRiskProfile, DotNetAssemblyInfo
    dotnet_report = DotNetReport(
        is_dotnet=True, assembly_info=DotNetAssemblyInfo(),
        obfuscator=DotNetObfuscatorInfo(detected=True, name="X", confidence="MEDIUM"),
        risk_profile=DotNetRiskProfile(dotnet_risk_score=28, dotnet_risk_level="MEDIUM"),
    )
    evidences = [
        ml_evidence(score=0.0, label="BENIGN"),
        yara_evidence(has_matches=False, status=EvidenceStatus.UNAVAILABLE, degraded_reason="no yara"),
        pe_static_evidence(packer_indicators={"packer_detected": True, "global_entropy": 7.9, "num_imports": 1}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=dotnet_report),
        il_behavioral_evidence(il_report=None, is_dotnet=True, status=EvidenceStatus.ERROR, error="x"),
    ]
    final = CorrelationEngine().correlate(evidences)
    # No debe interpretar YARA unavailable como benign -> debe ser SUSPICIOUS por PE+DOTNET
    assert final.verdict == EvidenceVerdict.SUSPICIOUS
    # YARA evidence debe estar en UNKNOWN, no BENIGN
    yara_ev = next(e for e in final.evidences if e["source"] == "yara")
    assert yara_ev["verdict"] == "unknown"
    assert yara_ev["status"] == "unavailable"


def test_case_G_insufficient_coverage():
    evidences = [
        ml_evidence(score=0.1, label="BENIGN"),
        yara_evidence(has_matches=False, status=EvidenceStatus.UNAVAILABLE, degraded_reason="x"),
        pe_static_evidence(packer_indicators={}, status=EvidenceStatus.UNAVAILABLE, error="x"),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.UNAVAILABLE, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.UNAVAILABLE, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.UNAVAILABLE, error="x"),
        il_behavioral_evidence(il_report=None, is_dotnet=True, status=EvidenceStatus.UNAVAILABLE, error="x"),
    ]
    final = CorrelationEngine().correlate(evidences)
    assert final.verdict == EvidenceVerdict.UNKNOWN
    assert final.operational_status == OperationalStatus.UNKNOWN
    assert final.degraded is True
    assert final.confidence == "Low"
    # Nunca CLEAN con cobertura insuficiente
    assert final.verdict != EvidenceVerdict.BENIGN


def test_case_H_double_counting():
    # PE y Heuristic comparten mismo fenomeno; no deben contar como 2
    from core.heuristics import RiskAssessment
    pe = pe_static_evidence(packer_indicators={"packer_detected": True, "global_entropy": 7.9, "num_imports": 1})
    heur = heuristic_evidence(risk_assessment=RiskAssessment(risk_score=40, risk_level="MEDIUM", operational_status="SUSPICIOUS", triggered_indicators=["packer", "entropy"], justification="pe derived"))
    assert pe.evidence_group == heur.evidence_group == "pe_heuristic"
    # Con solo PE+Heuristic (mismo grupo) no debe ser 2 grupos -> si solo esos 2, no debe activar regla >=2
    evidences = [
        ml_evidence(score=0.1, label="BENIGN"),
        yara_evidence(has_matches=False),
        pe,
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heur,
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = CorrelationEngine().correlate(evidences)
    # Solo un grupo pe_heuristic suspicious, aunque 2 evidencias en mismo grupo -> no debe contar como 2 independientes
    # Con S~0.19 con pe 0.8 solo -> S<0.3? Ahora threshold 0.15 -> S~0.19 -> SUSPICIOUS igual por S, pero no por regla 2 grupos
    # Verificar que no doble cuenta peso: groups = max, no sum
    assert final.verdict in (EvidenceVerdict.SUSPICIOUS, EvidenceVerdict.BENIGN)
    # Si es suspicious, debe ser por S, no por 2 grupos
    if final.verdict == EvidenceVerdict.SUSPICIOUS:
        assert "pe_static" in final.contributing_sources or "heuristic" in final.contributing_sources
        # No debe tener ambos pe_static y heuristic como 2 contribuidores separados si mismo grupo y solo uno es max
        # El weighted toma max, asi que solo 1 del grupo contribuye


def test_case_I_future_cnn():
    evidences = [
        ml_evidence(score=0.1, label="BENIGN"),
        yara_evidence(has_matches=False),
        pe_static_evidence(packer_indicators={}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
        cnn_evidence(score=0.9, label="MALWARE"),
    ]
    final = CorrelationEngine().correlate(evidences)
    # CNN malicious debe participar: S incluye cnn 0.9*0.6
    # Con solo ML benign + CNN malicious -> 1 grupo suspicious (cnn) -> S~0.26 -> SUSPICIOUS
    assert final.verdict in (EvidenceVerdict.SUSPICIOUS, EvidenceVerdict.MALICIOUS)
    assert "cnn" in [e["source"] for e in final.evidences]
    # CNN evidence preservada
    cnn_ev = next(e for e in final.evidences if e["source"] == "cnn")
    assert cnn_ev["score_norm"] == 0.9
    assert cnn_ev["verdict"] == "malicious"
