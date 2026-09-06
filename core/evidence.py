"""
core/evidence.py — Evidence Contract para arquitectura multicapa (F2 Final).

Cada capa produce una Evidence independiente que el CorrelationEngine
agrega sin "last writer wins". F2 Final anade:
  - score_raw (preservado) + score_norm (0-1) + scale
  - reliability (0-1) explicita por naturaleza de fuente
  - evidence_group / dependency cluster para anti-double-counting
  - confidence / degraded handling
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class EvidenceSource(str, Enum):
    ML_ONNX = "ml_onnx"
    YARA = "yara"
    PE_STATIC = "pe_static"
    OVERLAY = "overlay"
    HEURISTIC = "heuristic"
    DOTNET = "dotnet"
    IL_BEHAVIORAL = "il_behavioral"
    CNN = "cnn"


class EvidenceVerdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OperationalStatus(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    UNKNOWN = "unknown"


class EvidenceStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class Reliability(str, Enum):
    """Naturaleza de confiabilidad. Valor numerico via ReliabilityWeight."""
    DETERMINISTIC = "deterministic"  # YARA match especifico
    HIGH = "high"                    # IL MemberRef, Overlay embedded_pe
    MEDIUM = "medium"                # ML calibrado, PE heuristic
    LOW = "low"                      # DOTNET contextual, Heuristic derivado
    DEGRADED = "degraded"            # ML con scaler drift / capa degradada


# Pesos iniciales auditables (no calibrados estadisticamente).
# Sujetos a futura calibracion con corpus. Documentado en contrato.
ReliabilityWeight: Dict[Reliability, float] = {
    Reliability.DETERMINISTIC: 1.0,
    Reliability.HIGH: 0.85,
    Reliability.MEDIUM: 0.6,
    Reliability.LOW: 0.35,
    Reliability.DEGRADED: 0.25,
}

# Escalas nativas por fuente (para normalizacion 0-1)
ScaleMax: Dict[EvidenceSource, float] = {
    EvidenceSource.ML_ONNX: 1.0,
    EvidenceSource.YARA: 1.0,
    EvidenceSource.PE_STATIC: 50.0,   # max suma pe_static (ver pe_static_evidence)
    EvidenceSource.OVERLAY: 60.0,     # 30+25+35 ~60
    EvidenceSource.HEURISTIC: 100.0,  # clamp 100, umbrales 0-20/21-50/51-79/80+
    EvidenceSource.DOTNET: 100.0,     # idem
    EvidenceSource.IL_BEHAVIORAL: 100.0,
    EvidenceSource.CNN: 1.0,
}

# Grupos de evidencia para anti-double-counting.
# Dos evidencias en mismo cluster comparten fenomeno informativo.
EvidenceGroup = str
GROUP_ML_PROB: EvidenceGroup = "ml_prob"
GROUP_YARA_SIG: EvidenceGroup = "yara_sig"
GROUP_PE_HEURISTIC: EvidenceGroup = "pe_heuristic"  # pe_static <-> heuristic comparten entropy/packer/imports
GROUP_OVERLAY: EvidenceGroup = "overlay_forensic"
GROUP_DOTNET_META: EvidenceGroup = "dotnet_meta"
GROUP_IL_SEMANTIC: EvidenceGroup = "il_semantic"
GROUP_CNN_PROB: EvidenceGroup = "cnn_prob"

SourceGroup: Dict[EvidenceSource, EvidenceGroup] = {
    EvidenceSource.ML_ONNX: GROUP_ML_PROB,
    EvidenceSource.YARA: GROUP_YARA_SIG,
    EvidenceSource.PE_STATIC: GROUP_PE_HEURISTIC,
    EvidenceSource.HEURISTIC: GROUP_PE_HEURISTIC,
    EvidenceSource.OVERLAY: GROUP_OVERLAY,
    EvidenceSource.DOTNET: GROUP_DOTNET_META,
    EvidenceSource.IL_BEHAVIORAL: GROUP_IL_SEMANTIC,
    EvidenceSource.CNN: GROUP_CNN_PROB,
}


def _norm(raw: Optional[float], source: EvidenceSource) -> Optional[float]:
    if raw is None:
        return None
    scale = ScaleMax.get(source, 1.0)
    if scale <= 0:
        return 0.0
    # ML/CNN/YARA ya 0-1, otros 0-scale -> 0-1 clamp
    if source in (EvidenceSource.ML_ONNX, EvidenceSource.YARA, EvidenceSource.CNN):
        return max(0.0, min(1.0, float(raw)))
    return max(0.0, min(1.0, float(raw) / scale))


@dataclass
class EvidenceIndicator:
    name: str
    value: Any = None
    weight: int = 0
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "value": self.value, "weight": self.weight, "description": self.description}


@dataclass
class Evidence:
    source: EvidenceSource
    verdict: EvidenceVerdict
    # score (compat) alias a score_raw; preferir score_raw/score_norm
    score: Optional[float] = None
    score_raw: Optional[float] = None
    score_norm: Optional[float] = None  # 0-1
    scale: Optional[str] = None
    severity: Severity = Severity.LOW
    operational_status: OperationalStatus = OperationalStatus.CLEAN
    indicators: List[EvidenceIndicator] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: EvidenceStatus = EvidenceStatus.OK
    error: Optional[str] = None
    # Nuevos campos F2
    reliability: Reliability = Reliability.MEDIUM
    reliability_weight: float = 0.6
    evidence_group: EvidenceGroup = ""
    confidence: str = "Low"  # Low/Medium/High para UI

    def __post_init__(self):
        # Compat: si solo score viene, copiar a raw/norm
        if self.score is not None and self.score_raw is None:
            self.score_raw = self.score
        if self.score_raw is not None and self.score_norm is None:
            self.score_norm = _norm(self.score_raw, self.source)
        if self.score is None and self.score_raw is not None:
            self.score = self.score_raw
        if not self.evidence_group:
            self.evidence_group = SourceGroup.get(self.source, "")
        if self.reliability_weight == 0.6 and self.reliability in ReliabilityWeight:
            # si no se paso peso custom, usar default por reliability
            self.reliability_weight = ReliabilityWeight[self.reliability]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.value,
            "verdict": self.verdict.value,
            "score": self.score,
            "score_raw": self.score_raw,
            "score_norm": self.score_norm,
            "scale": self.scale or ScaleMax.get(self.source, 1.0),
            "severity": self.severity.value,
            "operational_status": self.operational_status.value,
            "indicators": [i.to_dict() for i in self.indicators],
            "reasons": list(self.reasons),
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp,
            "status": self.status.value,
            "error": self.error,
            "reliability": self.reliability.value,
            "reliability_weight": self.reliability_weight,
            "evidence_group": self.evidence_group,
            "confidence": self.confidence,
        }

    @property
    def is_available(self) -> bool:
        return self.status in (EvidenceStatus.OK, EvidenceStatus.DEGRADED)

    @property
    def is_degraded(self) -> bool:
        return self.status == EvidenceStatus.DEGRADED

    @property
    def is_error(self) -> bool:
        return self.status in (EvidenceStatus.ERROR, EvidenceStatus.UNAVAILABLE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def ml_evidence(
    *,
    score: float,
    label: str,
    confidence: str = "Low",
    status: EvidenceStatus = EvidenceStatus.OK,
    error: Optional[str] = None,
    degraded: bool = False,
) -> Evidence:
    from configs.settings import MALWARE_THRESHOLD
    if status in (EvidenceStatus.ERROR, EvidenceStatus.UNAVAILABLE):
        return Evidence(
            source=EvidenceSource.ML_ONNX, verdict=EvidenceVerdict.UNKNOWN,
            score=None, score_raw=None, score_norm=None, scale="prob_0_1",
            severity=Severity.LOW, operational_status=OperationalStatus.UNKNOWN,
            reasons=[error or "ML unavailable"], status=status, error=error,
            reliability=Reliability.DEGRADED, evidence_group=GROUP_ML_PROB,
            confidence="Low", timestamp=_now(),
        )
    reliability = Reliability.DEGRADED if degraded else Reliability.MEDIUM
    if score >= MALWARE_THRESHOLD:
        verdict = EvidenceVerdict.MALICIOUS
        severity = Severity.CRITICAL if score >= 0.85 else Severity.HIGH
        op = OperationalStatus.DANGEROUS
        conf = "High" if confidence == "High" else "Medium"
    elif score >= 0.4:
        verdict = EvidenceVerdict.SUSPICIOUS
        severity = Severity.MEDIUM
        op = OperationalStatus.SUSPICIOUS
        conf = "Medium"
    else:
        verdict = EvidenceVerdict.BENIGN
        severity = Severity.LOW
        op = OperationalStatus.CLEAN
        conf = confidence
    return Evidence(
        source=EvidenceSource.ML_ONNX, verdict=verdict,
        score=score, score_raw=score, score_norm=_norm(score, EvidenceSource.ML_ONNX),
        scale="prob_0_1", severity=severity, operational_status=op,
        reasons=[f"ml_score={score:.4f} threshold={MALWARE_THRESHOLD} confidence={confidence}"],
        metadata={"confidence": confidence, "threshold": MALWARE_THRESHOLD},
        status=status, reliability=reliability, evidence_group=GROUP_ML_PROB,
        confidence=conf, timestamp=_now(),
    )


def yara_evidence(
    *,
    has_matches: bool,
    matches: Optional[List[Dict[str, Any]]] = None,
    threat_names: Optional[List[str]] = None,
    status: EvidenceStatus = EvidenceStatus.OK,
    error: Optional[str] = None,
    degraded_reason: Optional[str] = None,
) -> Evidence:
    if status == EvidenceStatus.UNAVAILABLE:
        return Evidence(
            source=EvidenceSource.YARA, verdict=EvidenceVerdict.UNKNOWN,
            score=None, score_raw=None, score_norm=None, scale="deterministic",
            severity=Severity.LOW, operational_status=OperationalStatus.UNKNOWN,
            reasons=[degraded_reason or error or "YARA unavailable"],
            status=status, error=error or degraded_reason,
            reliability=Reliability.LOW, evidence_group=GROUP_YARA_SIG,
            confidence="Low", timestamp=_now(),
        )
    if status == EvidenceStatus.ERROR:
        return Evidence(
            source=EvidenceSource.YARA, verdict=EvidenceVerdict.UNKNOWN,
            score=None, score_raw=None, score_norm=None, scale="deterministic",
            severity=Severity.LOW, operational_status=OperationalStatus.UNKNOWN,
            reasons=[error or "YARA error"], status=status, error=error,
            reliability=Reliability.DEGRADED, evidence_group=GROUP_YARA_SIG,
            confidence="Low", timestamp=_now(),
        )
    if has_matches:
        return Evidence(
            source=EvidenceSource.YARA, verdict=EvidenceVerdict.MALICIOUS,
            score=1.0, score_raw=1.0, score_norm=1.0, scale="deterministic",
            severity=Severity.CRITICAL, operational_status=OperationalStatus.DANGEROUS,
            indicators=[EvidenceIndicator(name=m.get("rule", "?"), value=m, weight=35) for m in (matches or [])],
            reasons=[f"yara_match: {t}" for t in (threat_names or [])] or ["yara_match"],
            metadata={"threat_names": threat_names or [], "match_count": len(matches or [])},
            status=EvidenceStatus.OK, reliability=Reliability.DETERMINISTIC,
            evidence_group=GROUP_YARA_SIG, confidence="High", timestamp=_now(),
        )
    return Evidence(
        source=EvidenceSource.YARA, verdict=EvidenceVerdict.BENIGN,
        score=0.0, score_raw=0.0, score_norm=0.0, scale="deterministic",
        severity=Severity.LOW, operational_status=OperationalStatus.CLEAN,
        reasons=["no yara matches"], status=EvidenceStatus.OK,
        reliability=Reliability.MEDIUM, evidence_group=GROUP_YARA_SIG,
        confidence="Medium", timestamp=_now(),
    )


def pe_static_evidence(
    *,
    packer_indicators: Optional[Dict[str, Any]] = None,
    status: EvidenceStatus = EvidenceStatus.OK,
    error: Optional[str] = None,
) -> Evidence:
    if status in (EvidenceStatus.ERROR, EvidenceStatus.UNAVAILABLE):
        return Evidence(
            source=EvidenceSource.PE_STATIC, verdict=EvidenceVerdict.UNKNOWN,
            score=None, score_raw=None, score_norm=None, scale="heuristic_0_50",
            severity=Severity.LOW, operational_status=OperationalStatus.UNKNOWN,
            reasons=[error or "PE static unavailable"], status=status, error=error,
            reliability=Reliability.DEGRADED, evidence_group=GROUP_PE_HEURISTIC,
            confidence="Low", timestamp=_now(),
        )
    pi = packer_indicators or {}
    indicators: List[EvidenceIndicator] = []
    reasons: List[str] = []
    score = 0
    if pi.get("packer_detected"):
        indicators.append(EvidenceIndicator(name="packer_detected", value=True, weight=10, description="packer signature"))
        reasons.append("packer_detected"); score += 10
    if pi.get("global_entropy", 0) > 7.5:
        indicators.append(EvidenceIndicator(name="high_global_entropy", value=pi["global_entropy"], weight=15))
        reasons.append(f"global_entropy={pi['global_entropy']:.2f} > 7.5"); score += 15
    if pi.get("rwx_sections", 0) > 0:
        indicators.append(EvidenceIndicator(name="rwx_sections", value=pi["rwx_sections"], weight=15))
        reasons.append(f"rwx_sections={pi['rwx_sections']}"); score += 15
    if pi.get("num_imports", -1) == 0:
        indicators.append(EvidenceIndicator(name="no_imports", value=0, weight=20))
        reasons.append("no_imports"); score += 20
    elif 0 < pi.get("num_imports", -1) < 10:
        indicators.append(EvidenceIndicator(name="very_low_imports", value=pi["num_imports"], weight=15))
        reasons.append(f"very_low_imports={pi['num_imports']}"); score += 15
    verdict = EvidenceVerdict.SUSPICIOUS if score >= 20 else EvidenceVerdict.BENIGN
    sev = Severity.MEDIUM if score >= 20 else Severity.LOW
    op = OperationalStatus.SUSPICIOUS if score >= 20 else OperationalStatus.CLEAN
    return Evidence(
        source=EvidenceSource.PE_STATIC, verdict=verdict,
        score=float(score), score_raw=float(score), score_norm=_norm(float(score), EvidenceSource.PE_STATIC),
        scale="heuristic_0_50", severity=sev, operational_status=op,
        indicators=indicators, reasons=reasons or ["no pe_static indicators"],
        metadata=dict(pi), status=status, reliability=Reliability.MEDIUM,
        evidence_group=GROUP_PE_HEURISTIC, confidence="Medium" if verdict==EvidenceVerdict.SUSPICIOUS else "Low",
        timestamp=_now(),
    )


def overlay_evidence(
    *,
    overlay_report: Optional[Any] = None,
    status: EvidenceStatus = EvidenceStatus.OK,
    error: Optional[str] = None,
) -> Evidence:
    if status in (EvidenceStatus.ERROR, EvidenceStatus.UNAVAILABLE) or overlay_report is None:
        return Evidence(
            source=EvidenceSource.OVERLAY, verdict=EvidenceVerdict.UNKNOWN,
            score=None, score_raw=None, score_norm=None, scale="heuristic_0_60",
            severity=Severity.LOW, operational_status=OperationalStatus.UNKNOWN,
            reasons=[error or "overlay unavailable"],
            status=status if overlay_report is None and status != EvidenceStatus.OK else EvidenceStatus.ERROR,
            error=error, reliability=Reliability.DEGRADED, evidence_group=GROUP_OVERLAY,
            confidence="Low", timestamp=_now(),
        )
    indicators: List[EvidenceIndicator] = []
    reasons: List[str] = []
    # Detect high reliability case: embedded_pe is near-deterministic
    has_embedded = False
    if getattr(overlay_report, "overlay_present", False):
        ratio = getattr(overlay_report, "overlay_ratio", 0.0)
        ent = getattr(overlay_report, "overlay_entropy", 0.0)
        indicators.append(EvidenceIndicator(name="overlay_present", value=True, weight=0, description=f"ratio={ratio:.2%} entropy={ent:.2f}"))
        reasons.append(f"overlay_present ratio={ratio:.2%} entropy={ent:.2f}")
        if ratio > 0.80:
            indicators.append(EvidenceIndicator(name="overlay_ratio_high", value=ratio, weight=30))
            reasons.append(f"overlay_ratio={ratio:.1%} > 80%")
        if getattr(overlay_report, "embedded_pe_detected", False):
            indicators.append(EvidenceIndicator(name="embedded_pe", value=getattr(overlay_report, "embedded_pe_count", 0), weight=25))
            reasons.append(f"embedded_pe_count={getattr(overlay_report, 'embedded_pe_count', 0)}")
            has_embedded = True
        if getattr(overlay_report, "overlay_yara_hits", []):
            indicators.append(EvidenceIndicator(name="yara_overlay", value=getattr(overlay_report, "overlay_yara_hits", []), weight=35))
            reasons.append(f"yara_overlay={getattr(overlay_report, 'overlay_yara_hits', [])}")
            has_embedded = True
    weighted = sum(i.weight for i in indicators)
    has_signal = weighted > 0 and any(i.weight > 0 for i in indicators)
    verdict = EvidenceVerdict.SUSPICIOUS if has_signal else EvidenceVerdict.BENIGN
    sev = Severity.MEDIUM if has_signal else Severity.LOW
    # embedded_pe is HIGH reliability deterministic-like
    if has_embedded:
        sev = Severity.CRITICAL
        verdict = EvidenceVerdict.MALICIOUS
        op = OperationalStatus.DANGEROUS
        rel = Reliability.HIGH
    else:
        op = OperationalStatus.SUSPICIOUS if has_signal else OperationalStatus.CLEAN
        rel = Reliability.MEDIUM if has_signal else Reliability.LOW
    return Evidence(
        source=EvidenceSource.OVERLAY, verdict=verdict,
        score=float(weighted), score_raw=float(weighted), score_norm=_norm(float(weighted), EvidenceSource.OVERLAY),
        scale="heuristic_0_60", severity=sev, operational_status=op,
        indicators=indicators, reasons=reasons or ["no overlay signals"],
        metadata=overlay_report.to_dict() if hasattr(overlay_report, "to_dict") else {},
        status=EvidenceStatus.OK, reliability=rel, evidence_group=GROUP_OVERLAY,
        confidence="High" if has_embedded else ("Medium" if has_signal else "Low"),
        timestamp=_now(),
    )


def heuristic_evidence(
    *,
    risk_assessment: Optional[Any] = None,
    status: EvidenceStatus = EvidenceStatus.OK,
    error: Optional[str] = None,
) -> Evidence:
    if status in (EvidenceStatus.ERROR, EvidenceStatus.UNAVAILABLE) or risk_assessment is None:
        return Evidence(
            source=EvidenceSource.HEURISTIC, verdict=EvidenceVerdict.UNKNOWN,
            score=None, score_raw=None, score_norm=None, scale="heuristic_0_100",
            severity=Severity.LOW, operational_status=OperationalStatus.UNKNOWN,
            reasons=[error or "heuristic unavailable"],
            status=status if risk_assessment is None and status != EvidenceStatus.OK else EvidenceStatus.ERROR,
            error=error, reliability=Reliability.DEGRADED, evidence_group=GROUP_PE_HEURISTIC,
            confidence="Low", timestamp=_now(),
        )
    score = getattr(risk_assessment, "risk_score", 0)
    level = getattr(risk_assessment, "risk_level", "LOW")
    op_str = getattr(risk_assessment, "operational_status", "CLEAN")
    sev_map = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}
    op_map = {"CLEAN": OperationalStatus.CLEAN, "SUSPICIOUS": OperationalStatus.SUSPICIOUS, "DANGEROUS": OperationalStatus.DANGEROUS}
    verdict_map = {"LOW": EvidenceVerdict.BENIGN, "MEDIUM": EvidenceVerdict.SUSPICIOUS, "HIGH": EvidenceVerdict.SUSPICIOUS, "CRITICAL": EvidenceVerdict.MALICIOUS}
    return Evidence(
        source=EvidenceSource.HEURISTIC, verdict=verdict_map.get(level, EvidenceVerdict.BENIGN),
        score=float(score), score_raw=float(score), score_norm=_norm(float(score), EvidenceSource.HEURISTIC),
        scale="heuristic_0_100", severity=sev_map.get(level, Severity.LOW),
        operational_status=op_map.get(op_str, OperationalStatus.CLEAN),
        indicators=[EvidenceIndicator(name=t, value=t, weight=0) for t in getattr(risk_assessment, "triggered_indicators", [])],
        reasons=list(getattr(risk_assessment, "triggered_indicators", [])) or [getattr(risk_assessment, "justification", "")],
        metadata=risk_assessment.to_dict() if hasattr(risk_assessment, "to_dict") else {"risk_score": score, "risk_level": level},
        status=EvidenceStatus.OK, reliability=Reliability.LOW, evidence_group=GROUP_PE_HEURISTIC,
        confidence="Low", timestamp=_now(),
    )


def dotnet_evidence(
    *,
    dotnet_report: Optional[Any] = None,
    status: EvidenceStatus = EvidenceStatus.OK,
    error: Optional[str] = None,
) -> Evidence:
    if dotnet_report is None or not getattr(dotnet_report, "is_dotnet", False):
        if status in (EvidenceStatus.ERROR, EvidenceStatus.UNAVAILABLE):
            return Evidence(
                source=EvidenceSource.DOTNET, verdict=EvidenceVerdict.UNKNOWN,
                score=None, score_raw=None, score_norm=None, scale="heuristic_0_100",
                severity=Severity.LOW, operational_status=OperationalStatus.UNKNOWN,
                reasons=[error or "dotnet unavailable"], status=status, error=error,
                reliability=Reliability.DEGRADED, evidence_group=GROUP_DOTNET_META,
                confidence="Low", timestamp=_now(),
            )
        return Evidence(
            source=EvidenceSource.DOTNET, verdict=EvidenceVerdict.BENIGN,
            score=0.0, score_raw=0.0, score_norm=0.0, scale="heuristic_0_100",
            severity=Severity.LOW, operational_status=OperationalStatus.CLEAN,
            reasons=["not_dotnet"], metadata={"is_dotnet": False},
            status=EvidenceStatus.OK, reliability=Reliability.LOW,
            evidence_group=GROUP_DOTNET_META, confidence="Low", timestamp=_now(),
        )
    rp = getattr(dotnet_report, "risk_profile", None)
    score = getattr(rp, "dotnet_risk_score", 0) if rp else 0
    level = getattr(rp, "dotnet_risk_level", "LOW") if rp else "LOW"
    sev_map = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}
    op_map = {"LOW": OperationalStatus.CLEAN, "MEDIUM": OperationalStatus.CLEAN, "HIGH": OperationalStatus.SUSPICIOUS, "CRITICAL": OperationalStatus.DANGEROUS}
    verdict_map = {"LOW": EvidenceVerdict.BENIGN, "MEDIUM": EvidenceVerdict.SUSPICIOUS, "HIGH": EvidenceVerdict.SUSPICIOUS, "CRITICAL": EvidenceVerdict.MALICIOUS}
    obf = getattr(dotnet_report, "obfuscator", None)
    reasons: List[str] = []
    indicators: List[EvidenceIndicator] = []
    if obf and getattr(obf, "detected", False):
        reasons.append(f"obfuscator={getattr(obf, 'name', '?')} conf={getattr(obf, 'confidence', '?')}")
        indicators.append(EvidenceIndicator(name="obfuscator_detected", value=getattr(obf, "name", ""), weight=20))
    if rp and getattr(rp, "risk_factors", []):
        reasons.extend(list(getattr(rp, "risk_factors", []))[:4])
    sil = getattr(dotnet_report, "suspicious_il", None)
    if sil and getattr(sil, "reflection_usage", False):
        indicators.append(EvidenceIndicator(name="reflection_usage", value=True, weight=8))
        reasons.append("reflection_usage")
    if sil and getattr(sil, "dynamic_loading_detected", False):
        indicators.append(EvidenceIndicator(name="dynamic_loading", value=True, weight=15))
        reasons.append("dynamic_loading")
    return Evidence(
        source=EvidenceSource.DOTNET, verdict=verdict_map.get(level, EvidenceVerdict.BENIGN),
        score=float(score), score_raw=float(score), score_norm=_norm(float(score), EvidenceSource.DOTNET),
        scale="heuristic_0_100", severity=sev_map.get(level, Severity.LOW),
        operational_status=op_map.get(level, OperationalStatus.CLEAN),
        indicators=indicators, reasons=reasons or [f"dotnet_risk={level} score={score}"],
        metadata=dotnet_report.to_dict() if hasattr(dotnet_report, "to_dict") else {"dotnet_risk_score": score},
        status=EvidenceStatus.OK, reliability=Reliability.LOW, evidence_group=GROUP_DOTNET_META,
        confidence="Medium" if level in ("MEDIUM","HIGH") else "Low", timestamp=_now(),
    )


def il_behavioral_evidence(
    *,
    il_report: Optional[Any] = None,
    is_dotnet: bool = False,
    status: EvidenceStatus = EvidenceStatus.OK,
    error: Optional[str] = None,
) -> Evidence:
    if not is_dotnet:
        return Evidence(
            source=EvidenceSource.IL_BEHAVIORAL, verdict=EvidenceVerdict.BENIGN,
            score=0.0, score_raw=0.0, score_norm=0.0, scale="heuristic_0_100",
            severity=Severity.LOW, operational_status=OperationalStatus.CLEAN,
            reasons=["not_dotnet_no_il"], metadata={"is_dotnet": False},
            status=EvidenceStatus.OK, reliability=Reliability.LOW,
            evidence_group=GROUP_IL_SEMANTIC, confidence="Low", timestamp=_now(),
        )
    if il_report is None or status in (EvidenceStatus.ERROR, EvidenceStatus.UNAVAILABLE):
        return Evidence(
            source=EvidenceSource.IL_BEHAVIORAL, verdict=EvidenceVerdict.UNKNOWN,
            score=None, score_raw=None, score_norm=None, scale="heuristic_0_100",
            severity=Severity.LOW, operational_status=OperationalStatus.UNKNOWN,
            reasons=[error or "il unavailable"],
            status=status if il_report is None and status != EvidenceStatus.OK else EvidenceStatus.ERROR,
            error=error, reliability=Reliability.DEGRADED, evidence_group=GROUP_IL_SEMANTIC,
            confidence="Low", timestamp=_now(),
        )
    score = getattr(il_report, "dotnet_threat_score", 0)
    level = getattr(il_report, "dotnet_threat_level", "LOW")
    sev_map = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}
    op_map = {"LOW": OperationalStatus.CLEAN, "MEDIUM": OperationalStatus.SUSPICIOUS, "HIGH": OperationalStatus.SUSPICIOUS, "CRITICAL": OperationalStatus.DANGEROUS}
    verdict_map = {"LOW": EvidenceVerdict.BENIGN, "MEDIUM": EvidenceVerdict.SUSPICIOUS, "HIGH": EvidenceVerdict.SUSPICIOUS, "CRITICAL": EvidenceVerdict.MALICIOUS}
    indicators: List[EvidenceIndicator] = []
    for attr in ("injection", "persistence", "networking", "credential_theft", "worm", "stealer", "rat", "reflection", "dynamic_loading"):
        ind = getattr(il_report, attr, None)
        if ind and getattr(ind, "detected", False):
            indicators.append(EvidenceIndicator(name=attr, value=True, weight=getattr(ind, "score", 0)))
    # Determine reliability by source confidence: high if MemberRef else low if Fallback
    rel = Reliability.HIGH if any("MemberRef" in r for r in getattr(il_report, "all_evidence", [])) else (Reliability.MEDIUM if indicators else Reliability.LOW)
    return Evidence(
        source=EvidenceSource.IL_BEHAVIORAL, verdict=verdict_map.get(level, EvidenceVerdict.BENIGN),
        score=float(score), score_raw=float(score), score_norm=_norm(float(score), EvidenceSource.IL_BEHAVIORAL),
        scale="heuristic_0_100", severity=sev_map.get(level, Severity.LOW),
        operational_status=op_map.get(level, OperationalStatus.CLEAN),
        indicators=indicators,
        reasons=list(getattr(il_report, "all_evidence", [])[:6]) or [f"il_threat={level} score={score}"],
        metadata=il_report.to_dict() if hasattr(il_report, "to_dict") else {"dotnet_threat_score": score, "dotnet_threat_level": level},
        status=EvidenceStatus.OK, reliability=rel, evidence_group=GROUP_IL_SEMANTIC,
        confidence="High" if level=="CRITICAL" else ("Medium" if level in ("HIGH","MEDIUM") else "Low"),
        timestamp=_now(),
    )


def cnn_evidence(
    *,
    score: float,
    label: str = "UNKNOWN",
    status: EvidenceStatus = EvidenceStatus.OK,
    error: Optional[str] = None,
) -> Evidence:
    """Stub extensible para CNN futuro. No implementado, solo contrato."""
    if status in (EvidenceStatus.ERROR, EvidenceStatus.UNAVAILABLE):
        return Evidence(
            source=EvidenceSource.CNN, verdict=EvidenceVerdict.UNKNOWN,
            score=None, score_raw=None, score_norm=None, scale="prob_0_1",
            severity=Severity.LOW, operational_status=OperationalStatus.UNKNOWN,
            reasons=[error or "CNN unavailable"], status=status, error=error,
            reliability=Reliability.DEGRADED, evidence_group=GROUP_CNN_PROB,
            confidence="Low", timestamp=_now(),
        )
    verdict = EvidenceVerdict.MALICIOUS if score >= 0.5 else (EvidenceVerdict.SUSPICIOUS if score >= 0.4 else EvidenceVerdict.BENIGN)
    sev = Severity.CRITICAL if score >= 0.85 else (Severity.HIGH if score >= 0.5 else (Severity.MEDIUM if score >= 0.4 else Severity.LOW))
    op = OperationalStatus.DANGEROUS if verdict==EvidenceVerdict.MALICIOUS else (OperationalStatus.SUSPICIOUS if verdict==EvidenceVerdict.SUSPICIOUS else OperationalStatus.CLEAN)
    return Evidence(
        source=EvidenceSource.CNN, verdict=verdict,
        score=score, score_raw=score, score_norm=_norm(score, EvidenceSource.CNN),
        scale="prob_0_1", severity=sev, operational_status=op,
        reasons=[f"cnn_score={score:.4f}"], metadata={"label": label},
        status=status, reliability=Reliability.MEDIUM, evidence_group=GROUP_CNN_PROB,
        confidence="Medium", timestamp=_now(),
    )
