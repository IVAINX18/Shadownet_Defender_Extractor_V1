"""
core/correlation.py — Correlation Engine F2 Final.

Elimina last-writer-wins, usa score_norm + reliability + evidence_group.
No promedia raw scores incompatibles.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.evidence import (
    Evidence,
    EvidenceSource,
    EvidenceVerdict,
    EvidenceStatus,
    OperationalStatus,
    Reliability,
    Severity,
    GROUP_PE_HEURISTIC,
)


@dataclass
class FinalVerdict:
    verdict: EvidenceVerdict
    risk_level: Severity
    operational_status: OperationalStatus
    score: Optional[float]  # S agregado 0-1
    confidence: str
    reasons: List[str] = field(default_factory=list)
    contributing_sources: List[str] = field(default_factory=list)
    evidences: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ml_score_raw: Optional[float] = None
    degraded: bool = False
    coverage: float = 0.0  # 0-1
    contradiction: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "risk_level": self.risk_level.value,
            "operational_status": self.operational_status.value,
            "score": self.score,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "contributing_sources": list(self.contributing_sources),
            "evidences": list(self.evidences),
            "timestamp": self.timestamp,
            "ml_score_raw": self.ml_score_raw,
            "degraded": self.degraded,
            "coverage": self.coverage,
            "contradiction": self.contradiction,
        }


def _coverage(evidences: List[Evidence]) -> float:
    total = len(evidences)
    if total == 0:
        return 0.0
    avail = sum(1 for e in evidences if e.status in (EvidenceStatus.OK, EvidenceStatus.DEGRADED) and e.verdict != EvidenceVerdict.UNKNOWN)
    # UNKNOWN counts as unavailable for coverage
    return avail / total


def _contradiction(evidences: List[Evidence]) -> Optional[str]:
    by = {e.source.value: e for e in evidences}
    ml = by.get(EvidenceSource.ML_ONNX.value)
    # ML malicious vs rest benign
    if ml and ml.verdict == EvidenceVerdict.MALICIOUS and ml.status == EvidenceStatus.OK:
        others = [e for e in evidences if e.source != EvidenceSource.ML_ONNX and e.status == EvidenceStatus.OK and e.verdict == EvidenceVerdict.BENIGN]
        if len(others) >= 4:
            return f"ML malicious {ml.score_raw:.2f} contradicted by {len(others)} benign sources"
    # ML benign 0.0 vs 2+ suspicious
    if ml and ml.verdict == EvidenceVerdict.BENIGN and ml.score_norm is not None and ml.score_norm < 0.1:
        susp = [e for e in evidences if e.status == EvidenceStatus.OK and e.verdict in (EvidenceVerdict.SUSPICIOUS, EvidenceVerdict.MALICIOUS) and e.source != EvidenceSource.ML_ONNX]
        if len(susp) >= 2:
            return f"ML benign {ml.score_raw:.2f} contradicted by {len(susp)} suspicious sources ({','.join(s.source.value for s in susp[:3])})"
    return None


def _weighted_score(evidences: List[Evidence]) -> Tuple[Optional[float], List[str]]:
    """Calcula S = sum(w*s_norm)/sum(w) manejando groups para anti-double-counting."""
    # Agrupar por evidence_group, tomar max por grupo (no sumar pe+heuristic)
    groups: Dict[str, Evidence] = {}
    for e in evidences:
        if e.status not in (EvidenceStatus.OK, EvidenceStatus.DEGRADED):
            continue
        if e.verdict == EvidenceVerdict.UNKNOWN or e.score_norm is None:
            continue
        g = e.evidence_group
        # Para grupo pe_heuristic, tomar max score_norm * weight
        if g not in groups:
            groups[g] = e
        else:
            # comparar w*s
            cur = groups[g]
            cur_score = cur.score_norm if cur.score_norm is not None else 0.0
            e_score = e.score_norm if e.score_norm is not None else 0.0
            if (e.reliability_weight * e_score) > (cur.reliability_weight * cur_score):
                groups[g] = e
    if not groups:
        return None, []
    total_w = sum(e.reliability_weight for e in groups.values())
    total_ws = sum(e.reliability_weight * (e.score_norm if e.score_norm is not None else 0.0) for e in groups.values())
    S = total_ws / total_w if total_w > 0 else 0.0
    contributors = [e.source.value for e in groups.values() if e.verdict in (EvidenceVerdict.SUSPICIOUS, EvidenceVerdict.MALICIOUS)]
    return max(0.0, min(1.0, S)), contributors


def _verdict(S: Optional[float], evidences: List[Evidence], yara: Optional[Evidence], contradiction: Optional[str]) -> EvidenceVerdict:
    if yara and yara.status == EvidenceStatus.OK and yara.verdict == EvidenceVerdict.MALICIOUS:
        return EvidenceVerdict.MALICIOUS
    if S is None:
        return EvidenceVerdict.UNKNOWN
    # Regla robusta: 2+ grupos independientes sospechosos => al menos SUSPICIOUS
    groups_susp = set()
    for e in evidences:
        if e.status == EvidenceStatus.OK and e.verdict in (EvidenceVerdict.SUSPICIOUS, EvidenceVerdict.MALICIOUS):
            groups_susp.add(e.evidence_group)
    if len(groups_susp) >= 2:
        has_high = any(e.reliability in (Reliability.HIGH, Reliability.DETERMINISTIC) and e.verdict in (EvidenceVerdict.SUSPICIOUS, EvidenceVerdict.MALICIOUS) for e in evidences if e.status == EvidenceStatus.OK)
        if S is not None and S >= 0.60 and has_high:
            return EvidenceVerdict.MALICIOUS
        return EvidenceVerdict.SUSPICIOUS
    # S thresholds: 0.15 calibrado para que single PE 0.8 no se diluya por 4 benigns (S~0.19 -> SUSPICIOUS)
    if S < 0.15:
        return EvidenceVerdict.BENIGN
    if S < 0.60:
        return EvidenceVerdict.SUSPICIOUS
    has_high = any(e.reliability in (Reliability.HIGH, Reliability.DETERMINISTIC) and e.verdict in (EvidenceVerdict.SUSPICIOUS, EvidenceVerdict.MALICIOUS) for e in evidences if e.status == EvidenceStatus.OK)
    if has_high or (contradiction and "ML benign contradicted" in contradiction):
        if has_high:
            return EvidenceVerdict.MALICIOUS
        return EvidenceVerdict.SUSPICIOUS
    return EvidenceVerdict.SUSPICIOUS


def _risk(evidences: List[Evidence], verdict: EvidenceVerdict) -> Severity:
    # Risk = max severity entre evidencias sospechosas/maliciosas, mapeado
    sev_order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
    max_sev = Severity.LOW
    max_val = 0
    for e in evidences:
        if e.status != EvidenceStatus.OK:
            continue
        if e.verdict not in (EvidenceVerdict.SUSPICIOUS, EvidenceVerdict.MALICIOUS):
            continue
        v = sev_order.get(e.severity, 0)
        if v > max_val:
            max_val = v
            max_sev = e.severity
    if verdict == EvidenceVerdict.MALICIOUS:
        return Severity.CRITICAL if max_val >= 3 else Severity.HIGH
    if verdict == EvidenceVerdict.SUSPICIOUS:
        return max_sev if max_val >= 1 else Severity.MEDIUM
    if verdict == EvidenceVerdict.UNKNOWN:
        return Severity.LOW
    return Severity.LOW


def _operational(verdict: EvidenceVerdict, risk: Severity, evidences: List[Evidence], degraded: bool) -> OperationalStatus:
    if degraded and verdict == EvidenceVerdict.BENIGN:
        return OperationalStatus.UNKNOWN
    if verdict == EvidenceVerdict.MALICIOUS:
        return OperationalStatus.DANGEROUS
    if verdict == EvidenceVerdict.SUSPICIOUS:
        return OperationalStatus.SUSPICIOUS
    if verdict == EvidenceVerdict.UNKNOWN:
        return OperationalStatus.UNKNOWN
    # BENIGN
    # Si risk es HIGH/CRITICAL pero verdict BENIGN es inconsistente, elevar a SUSPICIOUS
    if risk in (Severity.HIGH, Severity.CRITICAL):
        return OperationalStatus.SUSPICIOUS
    return OperationalStatus.CLEAN


def _confidence(coverage: float, contradiction: Optional[str], S: Optional[float]) -> str:
    if coverage < 0.3:
        return "Low"
    if S is None:
        return "Low"
    # Contradiccion no fuerza Low si hay coverage alto y 2+ grupos (caso sample2)
    if contradiction and coverage < 0.8:
        return "Low"
    if coverage >= 0.8 and S is not None:
        return "High"
    return "Medium"


class CorrelationEngine:
    def correlate(self, evidences: List[Evidence]) -> FinalVerdict:
        by_source: Dict[str, Evidence] = {e.source.value: e for e in evidences}
        ml = by_source.get(EvidenceSource.ML_ONNX.value)
        yara = by_source.get(EvidenceSource.YARA.value)
        ml_score_raw = ml.score_raw if ml and ml.score_raw is not None else (ml.score if ml else None)

        coverage = _coverage(evidences)
        contradiction = _contradiction(evidences)

        # YARA deterministic
        if yara and yara.status == EvidenceStatus.OK and yara.verdict == EvidenceVerdict.MALICIOUS:
            return FinalVerdict(
                verdict=EvidenceVerdict.MALICIOUS, risk_level=Severity.CRITICAL,
                operational_status=OperationalStatus.DANGEROUS,
                score=yara.score_norm if yara.score_norm is not None else 1.0,
                confidence="High",
                reasons=[f"YARA determinista: {r}" for r in yara.reasons] + ["correlation: yara_overrides"],
                contributing_sources=[yara.source.value],
                evidences=[e.to_dict() for e in evidences],
                ml_score_raw=ml_score_raw, degraded=False, coverage=coverage, contradiction=contradiction,
            )

        # IL high-confidence semantic: MemberRef high reliability
        il = by_source.get(EvidenceSource.IL_BEHAVIORAL.value)
        if il and il.status == EvidenceStatus.OK and il.score_norm is not None:
            if il.score_norm >= 0.75:  # >=75 raw
                return FinalVerdict(
                    verdict=EvidenceVerdict.MALICIOUS, risk_level=Severity.CRITICAL,
                    operational_status=OperationalStatus.DANGEROUS,
                    score=il.score_norm, confidence="High",
                    reasons=[f"IL CRITICAL {il.score_raw:.0f}"] + il.reasons[:2],
                    contributing_sources=[il.source.value],
                    evidences=[e.to_dict() for e in evidences],
                    ml_score_raw=ml_score_raw, degraded=False, coverage=coverage, contradiction=contradiction,
                )
            if il.score_norm >= 0.50:
                return FinalVerdict(
                    verdict=EvidenceVerdict.SUSPICIOUS, risk_level=Severity.HIGH,
                    operational_status=OperationalStatus.SUSPICIOUS,
                    score=il.score_norm, confidence="Medium",
                    reasons=[f"IL HIGH {il.score_raw:.0f}"] + il.reasons[:2],
                    contributing_sources=[il.source.value],
                    evidences=[e.to_dict() for e in evidences],
                    ml_score_raw=ml_score_raw, degraded=False, coverage=coverage, contradiction=contradiction,
                )

        # Degraded / insufficient coverage
        # Si todas excepto ML unavailable y ML benign -> UNKNOWN
        unavailable = sum(1 for e in evidences if e.status in (EvidenceStatus.UNAVAILABLE, EvidenceStatus.ERROR) or e.verdict == EvidenceVerdict.UNKNOWN)
        if coverage < 0.3 or (unavailable >= 5 and ml and ml.verdict == EvidenceVerdict.BENIGN):
            # Insufficient evidence -> UNKNOWN, no CLEAN
            return FinalVerdict(
                verdict=EvidenceVerdict.UNKNOWN, risk_level=Severity.LOW,
                operational_status=OperationalStatus.UNKNOWN,
                score=None, confidence="Low",
                reasons=[f"insufficient coverage {coverage:.0%}"] + ([f"contradiction: {contradiction}"] if contradiction else []),
                contributing_sources=[],
                evidences=[e.to_dict() for e in evidences],
                ml_score_raw=ml_score_raw, degraded=True, coverage=coverage, contradiction=contradiction,
            )

        S, contributors = _weighted_score(evidences)
        verdict = _verdict(S, evidences, yara, contradiction)
        risk = _risk(evidences, verdict)
        degraded_flag = coverage < 0.3  # solo por cobertura, no por contradiccion sola
        operational = _operational(verdict, risk, evidences, degraded_flag)
        if degraded_flag and verdict == EvidenceVerdict.BENIGN:
            verdict = EvidenceVerdict.UNKNOWN
            operational = OperationalStatus.UNKNOWN
        confidence = _confidence(coverage, contradiction, S)
        reasons: List[str] = []
        if S is not None:
            reasons.append(f"S={S:.2f} coverage={coverage:.0%}")
        if contradiction:
            reasons.append(f"contradiction: {contradiction}")
        if contributors:
            reasons.append(f"contributors: {','.join(contributors)}")
        # Añadir razones de evidencias contribuyentes
        for src in contributors[:3]:
            ev = by_source.get(src)
            if ev and ev.reasons:
                reasons.append(f"{src}: {ev.reasons[0]}")

        return FinalVerdict(
            verdict=verdict, risk_level=risk, operational_status=operational,
            score=S, confidence=confidence, reasons=reasons,
            contributing_sources=contributors,
            evidences=[e.to_dict() for e in evidences],
            ml_score_raw=ml_score_raw, degraded=degraded_flag,
            coverage=coverage, contradiction=contradiction,
        )
