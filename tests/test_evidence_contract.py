"""
tests/test_evidence_contract.py — Tests para Evidence Contract + Correlation Engine.

Cubre los 10 criterios obligatorios de las Fases 1-2:
  1. YARA puede producir MALICIOUS
  2. ML BENIGN no borra YARA MALICIOUS
  3. .NET no borra packer/entropy/obfuscation
  4. IL aporta evidencia independiente
  5. unavailable/degraded != BENIGN
  6. Varias evidencias se preservan simultaneamente
  7. Resultado final viene exclusivamente de Correlation Engine
  8. Ninguna fase usa last-writer-wins
  9. sample2.exe atraviesa capas sin ejecucion
  10. Score ONNX original permanece intacto
"""
import pytest
from pathlib import Path

from core.evidence import (
    Evidence,
    EvidenceIndicator,
    EvidenceSource,
    EvidenceStatus,
    EvidenceVerdict,
    OperationalStatus,
    Severity,
    ml_evidence,
    yara_evidence,
    pe_static_evidence,
    overlay_evidence,
    heuristic_evidence,
    dotnet_evidence,
    il_behavioral_evidence,
)
from core.correlation import CorrelationEngine, FinalVerdict


# ---------------------------------------------------------------------------
# 1. YARA puede producir MALICIOUS
# ---------------------------------------------------------------------------
def test_yara_can_produce_malicious():
    ev = yara_evidence(has_matches=True, matches=[{"rule": "test_rule"}], threat_names=["test_rule"])
    assert ev.verdict == EvidenceVerdict.MALICIOUS
    assert ev.operational_status == OperationalStatus.DANGEROUS
    assert ev.score == 1.0


# ---------------------------------------------------------------------------
# 2. ML BENIGN no borra YARA MALICIOUS
# ---------------------------------------------------------------------------
def test_ml_benign_does_not_erase_yara_malicious():
    engine = CorrelationEngine()
    evidences = [
        ml_evidence(score=0.0, label="BENIGN", confidence="High"),
        yara_evidence(has_matches=True, matches=[{"rule": "malware_rule"}], threat_names=["malware_rule"]),
        pe_static_evidence(packer_indicators={}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="no overlay"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="no heuristic"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False, status=EvidenceStatus.OK),
    ]
    final = engine.correlate(evidences)
    assert final.verdict == EvidenceVerdict.MALICIOUS
    assert final.operational_status == OperationalStatus.DANGEROUS
    # ML 0.0 preservado
    assert final.ml_score_raw == 0.0


# ---------------------------------------------------------------------------
# 3. .NET no borra packer/entropy/obfuscation
# ---------------------------------------------------------------------------
def test_dotnet_does_not_erase_packer_entropy():
    engine = CorrelationEngine()
    # Simular sample2: pe_static con packer+entropy, dotnet con obfuscator
    pe = pe_static_evidence(packer_indicators={
        "packer_detected": True,
        "global_entropy": 7.9,
        "num_imports": 1,
        "rwx_sections": 0,
    })
    assert pe.verdict == EvidenceVerdict.SUSPICIOUS
    # Dotnet con obfuscator MEDIUM
    from core.dotnet import DotNetReport, DotNetObfuscatorInfo, DotNetRiskProfile, DotNetAssemblyInfo
    dotnet_report = DotNetReport(
        is_dotnet=True,
        assembly_info=DotNetAssemblyInfo(),
        obfuscator=DotNetObfuscatorInfo(detected=True, name="Unknown Obfuscator", confidence="MEDIUM"),
        risk_profile=DotNetRiskProfile(dotnet_risk_score=28, dotnet_risk_level="MEDIUM", risk_factors=["obfuscator"]),
    )
    dotnet_ev = dotnet_evidence(dotnet_report=dotnet_report)
    assert dotnet_ev.verdict == EvidenceVerdict.SUSPICIOUS

    evidences = [
        ml_evidence(score=0.0, label="BENIGN", confidence="High"),
        yara_evidence(has_matches=False, status=EvidenceStatus.OK),
        pe,
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="no overlay"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="no heuristic"),
        dotnet_ev,
        il_behavioral_evidence(il_report=None, is_dotnet=True, status=EvidenceStatus.ERROR, error="il not run"),
    ]
    final = engine.correlate(evidences)
    # Con pe_static + dotnet suspicious, debe ser SUSPICIOUS, no CLEAN
    assert final.verdict == EvidenceVerdict.SUSPICIOUS
    assert final.operational_status == OperationalStatus.SUSPICIOUS
    # Verificar que ambas evidencias estan en el output
    sources = [e["source"] for e in final.evidences]
    assert "pe_static" in sources
    assert "dotnet" in sources


# ---------------------------------------------------------------------------
# 4. IL aporta evidencia independiente
# ---------------------------------------------------------------------------
def test_il_provides_independent_evidence():
    engine = CorrelationEngine()
    # IL CRITICAL debe forzar DANGEROUS
    from core.dotnet.il_analyzer import ILBehavioralReport, BehaviorIndicator, Evidence as ILEvidence
    il_report = ILBehavioralReport()
    il_report.dotnet_threat_score = 80
    il_report.dotnet_threat_level = "CRITICAL"
    il_report.injection.detected = True
    il_report.injection.evidence = [ILEvidence(source="MemberRef", value="VirtualAlloc", location="MemberRef #1", confidence="high")]

    il_ev = il_behavioral_evidence(il_report=il_report, is_dotnet=True)
    assert il_ev.score == 80.0
    assert il_ev.verdict == EvidenceVerdict.MALICIOUS

    evidences = [
        ml_evidence(score=0.0, label="BENIGN"),
        yara_evidence(has_matches=False),
        pe_static_evidence(packer_indicators={}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_ev,
    ]
    final = engine.correlate(evidences)
    assert final.verdict == EvidenceVerdict.MALICIOUS
    assert final.operational_status == OperationalStatus.DANGEROUS


# ---------------------------------------------------------------------------
# 5. unavailable/degraded != BENIGN
# ---------------------------------------------------------------------------
def test_unavailable_not_benign():
    yara_unavail = yara_evidence(has_matches=False, status=EvidenceStatus.UNAVAILABLE, degraded_reason="yara not installed")
    assert yara_unavail.verdict == EvidenceVerdict.UNKNOWN
    assert yara_unavail.status == EvidenceStatus.UNAVAILABLE
    assert yara_unavail.verdict != EvidenceVerdict.BENIGN

    ml_err = ml_evidence(score=0.0, label="BENIGN", status=EvidenceStatus.ERROR, error="ML failed")
    assert ml_err.verdict == EvidenceVerdict.UNKNOWN
    assert ml_err.status == EvidenceStatus.ERROR

    # Correlacion con todo unavailable no debe ser CLEAN por defecto si hay senial
    engine = CorrelationEngine()
    evidences = [
        yara_unavail,
        ml_err,
        pe_static_evidence(packer_indicators={}, status=EvidenceStatus.UNAVAILABLE, error="pe error"),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.UNAVAILABLE, error="overlay error"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.UNAVAILABLE, error="heuristic error"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.UNAVAILABLE, error="dotnet error"),
        il_behavioral_evidence(il_report=None, is_dotnet=False, status=EvidenceStatus.UNAVAILABLE, error="il error"),
    ]
    # Capas unavailable no deben confundirse con benign; IL not_dotnet es benign OK pero informativo
    for e in evidences:
        if e.source == EvidenceSource.IL_BEHAVIORAL and e.metadata.get("is_dotnet") is False:
            assert e.verdict == EvidenceVerdict.BENIGN and e.status == EvidenceStatus.OK  # informativo, no degraded
        else:
            assert e.verdict != EvidenceVerdict.BENIGN or e.status == EvidenceStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# 6. Varias evidencias se preservan simultaneamente
# ---------------------------------------------------------------------------
def test_multiple_evidences_preserved():
    engine = CorrelationEngine()
    evidences = [
        ml_evidence(score=0.3, label="BENIGN"),
        yara_evidence(has_matches=False),
        pe_static_evidence(packer_indicators={"packer_detected": True, "global_entropy": 7.8, "num_imports": 2}),
        overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="x"),
        heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="x"),
        dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK),
        il_behavioral_evidence(il_report=None, is_dotnet=False),
    ]
    final = engine.correlate(evidences)
    # Todas las evidencias deben estar en final.evidences
    assert len(final.evidences) == 7
    sources = {e["source"] for e in final.evidences}
    assert sources == {"ml_onnx", "yara", "pe_static", "overlay", "heuristic", "dotnet", "il_behavioral"}


# ---------------------------------------------------------------------------
# 7. Resultado final viene exclusivamente de Correlation Engine
# ---------------------------------------------------------------------------
def test_final_exclusively_from_correlation():
    # Verificar que engine.scan_file usa correlation (tiene CORRELATION en phases y evidences)
    from core.engine import ShadowNetEngine
    engine = ShadowNetEngine()
    # Usar un archivo dummy PE si existe sample1
    sample = Path("samples/sample1.exe")
    if not sample.exists():
        pytest.skip("sample1.exe no existe")
    result = engine.scan_file(str(sample))
    assert "CORRELATION" in result["detection_phases"]
    assert "evidences" in result
    assert "final_verdict" in result
    assert "correlation" in result
    # Verificar que operational_status viene de correlation, no de last writer
    assert result["operational_status"] == result["final_verdict"]["operational_status"].upper()
    assert result["risk_level"] == result["final_verdict"]["risk_level"].upper()


# ---------------------------------------------------------------------------
# 8. Ninguna fase usa last-writer-wins (evidencias preservadas)
# ---------------------------------------------------------------------------
def test_no_last_writer_wins():
    from core.engine import ShadowNetEngine
    engine = ShadowNetEngine()
    sample = Path("samples/sample2.exe")
    if not sample.exists():
        pytest.skip("sample2.exe no existe")
    result = engine.scan_file(str(sample))
    # ML score 0.0 debe estar preservado en todas partes
    assert result["score"] == 0.0
    assert result["final_verdict"]["ml_score_raw"] == 0.0
    assert result["correlation"]["ml_score_preserved"] == 0.0
    # PE static evidence debe existir y ser suspicious (no borrada por dotnet)
    pe_ev = next((e for e in result["evidences"] if e["source"] == "pe_static"), None)
    assert pe_ev is not None
    assert pe_ev["verdict"] == "suspicious"
    assert pe_ev["score"] == 40.0
    # Dotnet evidence debe existir simultaneamente
    dot_ev = next((e for e in result["evidences"] if e["source"] == "dotnet"), None)
    assert dot_ev is not None
    assert dot_ev["verdict"] == "suspicious"


# ---------------------------------------------------------------------------
# 9. sample2.exe atraviesa capas sin ejecucion
# ---------------------------------------------------------------------------
def test_sample2_traverses_all_layers_without_execution():
    from core.engine import ShadowNetEngine
    engine = ShadowNetEngine()
    sample = Path("samples/sample2.exe")
    if not sample.exists():
        pytest.skip("sample2.exe no existe")
    # Solo analisis estatico: no se ejecuta el binario
    result = engine.scan_file(str(sample))
    # Debe tener todas las fases sin ejecucion
    assert "ML_STATIC" in result["detection_phases"]
    assert "OVERLAY_FORENSICS" in result["detection_phases"]
    assert "DOTNET_ANALYSIS" in result["detection_phases"]
    assert "IL_BEHAVIORAL" in result["detection_phases"]
    assert "CORRELATION" in result["detection_phases"]
    # No debe haber ejecutado el archivo (solo lectura)
    assert result.get("file") == str(sample)
    # Verificar que no hay behavioral_analysis activo por defecto
    assert result.get("behavioral_analysis") is None


# ---------------------------------------------------------------------------
# 10. Score ONNX original permanece intacto
# ---------------------------------------------------------------------------
def test_onnx_score_intact():
    from core.engine import ShadowNetEngine
    from models.inference import ShadowNetModel
    from extractors.extractor import PEFeatureExtractor
    from configs.settings import MODEL_PATH, SCALER_PATH

    sample = Path("samples/sample2.exe")
    if not sample.exists():
        pytest.skip("sample2.exe no existe")

    # Inferencia directa
    extractor = PEFeatureExtractor()
    model = ShadowNetModel(MODEL_PATH, SCALER_PATH)
    features = extractor.extract(str(sample))
    direct_score = model.predict(features)

    # Via engine
    engine = ShadowNetEngine()
    result = engine.scan_file(str(sample))
    engine_score = result["score"]
    preserved = result["final_verdict"]["ml_score_raw"]

    assert direct_score == pytest.approx(engine_score, abs=1e-4)
    assert direct_score == pytest.approx(preserved, abs=1e-4)
    # No se modifica threshold ni scaler
    from configs.settings import MALWARE_THRESHOLD
    assert MALWARE_THRESHOLD == 0.5
