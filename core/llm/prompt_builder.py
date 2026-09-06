from __future__ import annotations

import json
from typing import Any, Dict, List


def _safe_list(values: Any, *, max_items: int = 10) -> List[Any]:
    """
    Convierte a lista segura con límite de elementos para evitar prompts gigantes.
    """
    if not isinstance(values, list):
        return []
    return values[:max_items]


def _safe_top_features(values: Any, *, max_items: int = 5) -> List[Dict[str, Any]]:
    """
    Normaliza top features a una estructura controlada.
    """
    if not isinstance(values, list):
        return []

    normalized: List[Dict[str, Any]] = []
    for item in values[:max_items]:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "name": str(item.get("name", "unknown")),
                "value": item.get("value"),
                "impact": item.get("impact"),
            }
        )
    return normalized


def _as_float(value: Any) -> Any:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _summarize_evidence(ev: Any) -> Dict[str, Any]:
    """Resume una evidencia F1 a los campos relevantes para el LLM."""
    if not isinstance(ev, dict):
        return {}
    indicators = ev.get("indicators") or []
    names: List[str] = []
    if isinstance(indicators, list):
        for ind in indicators[:10]:
            if isinstance(ind, dict):
                names.append(str(ind.get("name", ind.get("value", "")))[:160])
            else:
                names.append(str(ind)[:160])
    reasons = ev.get("reasons") or []
    if isinstance(reasons, list):
        reasons = [str(r)[:300] for r in reasons[:8]]
    else:
        reasons = [str(reasons)[:300]]
    _meta = ev.get("metadata")
    meta: Dict[str, Any] = _meta if isinstance(_meta, dict) else {}
    # Recortar metadata a claves escalares relevantes para no inflar el prompt
    meta_trim: Dict[str, Any] = {}
    for k, v in list(meta.items())[:24]:
        if isinstance(v, (str, int, float, bool)) or v is None:
            meta_trim[str(k)] = v
        elif isinstance(v, list) and len(v) <= 8:
            meta_trim[str(k)] = [str(x)[:120] for x in v]
    return {
        "source": str(ev.get("source", "unknown")),
        "verdict": str(ev.get("verdict", "unknown")),
        "score_raw": ev.get("score_raw"),
        "score_norm": ev.get("score_norm"),
        "severity": str(ev.get("severity", "unknown")),
        "reliability": str(ev.get("reliability", "unknown")),
        "evidence_group": str(ev.get("evidence_group", "unknown")),
        "status": str(ev.get("status", "unknown")),
        "indicators": names,
        "reasons": reasons,
        "metadata": meta_trim,
    }


def extract_scan_summary(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrae el resumen del detector para el prompt del LLM (contrato F4.2).

    Lee el contrato ACTUAL del pipeline (ScanResult + F2 Evidence Contract):
    result / risk_level / operational_status / evidences / final_verdict /
    correlation / confidence / degraded / coverage / family_likelihoods.

    Compatibilidad: si el dict usa el esquema legacy (label/score/details),
    esos campos se propagan tal cual bajo la clave "legacy" para no perder
    informacion, pero el bloque autoritativo siempre es "detector".

    Seguridad:
    - No se envía el archivo completo ni datos crudos.
    - Nunca se inventan valores: lo ausente queda como None / "dato no disponible".
    """
    if not isinstance(scan_result, dict):
        return {"detector": {}, "evidences": [], "family": {}, "legacy": {}}

    final_verdict = scan_result.get("final_verdict")
    if not isinstance(final_verdict, dict):
        final_verdict = {}
    correlation = scan_result.get("correlation")
    if not isinstance(correlation, dict):
        correlation = {}

    # Veredicto autoritativo: final_verdict.verdict manda; fallback a result.
    verdict = (
        final_verdict.get("verdict")
        or scan_result.get("result")
        or scan_result.get("verdict")
    )
    risk = final_verdict.get("risk_level") or scan_result.get("risk_level")
    operational = final_verdict.get("operational_status") or scan_result.get("operational_status")
    corr_score = final_verdict.get("score")
    if corr_score is None:
        corr_score = correlation.get("score")

    detector = {
        "verdict": str(verdict).lower() if verdict is not None else None,
        "risk_level": str(risk).lower() if risk is not None else None,
        "operational_status": str(operational).upper() if operational is not None else None,
        "confidence": scan_result.get("confidence"),
        "degraded": scan_result.get("degraded"),
        "coverage": _as_float(scan_result.get("coverage")),
        "correlation_score": _as_float(corr_score),
        "correlation_verdict": str(
            correlation.get("verdict") or final_verdict.get("verdict") or ""
        ).lower() or None,
        "contributing_sources": _safe_list(
            final_verdict.get("contributing_sources")
            or correlation.get("contributing_sources")
            or [],
            max_items=10,
        ),
        "correlation_reasons": _safe_list(
            final_verdict.get("reasons") or correlation.get("reasons") or [],
            max_items=10,
        ),
        "contradiction": final_verdict.get("contradiction") or correlation.get("contradiction"),
        "ml_score_raw": _as_float(
            final_verdict.get("ml_score_raw", scan_result.get("ml_score_raw"))
        ),
        "file_name": scan_result.get("file_name"),
        "sha256": scan_result.get("sha256"),
        "analysis_type": scan_result.get("analysis_type"),
        "yara_matches": _safe_list(scan_result.get("yara_matches"), max_items=10),
    }

    raw_evidences = scan_result.get("evidences") or scan_result.get("evidence") or []
    evidences = (
        [_summarize_evidence(e) for e in raw_evidences[:12]]
        if isinstance(raw_evidences, list)
        else []
    )

    likelihoods = scan_result.get("family_likelihoods")
    if not isinstance(likelihoods, dict):
        # IL metadata tambien puede traer family_likelihoods anidadas
        likelihoods = {}
    top_family = scan_result.get("top_family") or None
    family = {
        "top_family": top_family,
        "family_likelihoods": {
            str(k): likelihoods[k] for k in list(likelihoods.keys())[:12]
        },
        "note": "family likelihood es hipotesis, no familia confirmada",
    }

    # Legacy passthrough (label/score/details) solo informativo
    details = scan_result.get("details", {})
    if not isinstance(details, dict):
        details = {}
    legacy = {
        "label": scan_result.get("label"),
        "score": scan_result.get("score"),
        "entropy": details.get("entropy"),
        "suspicious_imports": _safe_list(details.get("suspicious_imports")),
        "suspicious_sections": _safe_list(details.get("suspicious_sections")),
        "top_features": _safe_top_features(details.get("top_features")),
    }

    return {
        "detector": detector,
        "evidences": evidences,
        "family": family,
        "legacy": legacy,
    }


def build_llm_prompt(scan_result: Dict[str, Any]) -> str:
    """
    Construye un prompt robusto para explicaciones técnicas sin alucinaciones.

    Objetivo:
    - Producir un informe estructurado en JSON para analistas SOC.

    Reglas duras:
    - El modelo NO detecta malware; solo explica el resultado ya calculado.
    - El veredicto del detector es AUTORITATIVO: no puede modificarlo,
      contradecirlo ni reinterpretarlo como una clasificacion distinta.
    - Debe ceñirse exclusivamente a los datos entregados.
    - Si un campo no existe, debe indicarlo explícitamente como "dato no disponible".
    - family likelihood es hipotesis, nunca familia confirmada.
    """
    summary = extract_scan_summary(scan_result)
    data_block = json.dumps(summary, ensure_ascii=True, indent=2, default=str)

    return (
        "Rol: eres un analista de ciberseguridad especializado en malware.\n"
        "Contexto obligatorio: ShadowNet Defender ya clasificó el archivo y calculó su veredicto.\n"
        "Tu tarea NO es detectar malware; tu tarea es explicar el resultado con base en los datos de SCAN_SUMMARY.\n\n"
        "REGLA CRITICA — AUTORIDAD DEL DETECTOR:\n"
        "- El campo detector.verdict es AUTORITATIVO (benign | suspicious | malicious | unknown).\n"
        "- NO puedes modificarlo, contradecirlo ni reinterpretarlo como una clasificacion distinta.\n"
        "- Si detector.verdict es 'suspicious', tu threat_level debe ser 'medium', 'high' o 'critical' (NUNCA 'low' ni 'none').\n"
        "- Si detector.verdict es 'malicious', tu threat_level debe ser 'high' o 'critical'.\n"
        "- Si detector.verdict es 'benign', tu threat_level debe ser 'none' o 'low' (no inventes amenazas).\n"
        "- Explica SIEMPRE el veredicto con sus evidencias: 'El detector clasificó el archivo como X debido a ...'.\n"
        "- Si existen contradicciones entre fuentes (ej: ML benign pero PE/overlay suspicious), explícalas explícitamente.\n\n"
        "REGLA DE FAMILIA:\n"
        "- family.family_likelihoods son CANDIDATOS no concluyentes, no una familia confirmada.\n"
        "- Si no hay evidencia suficiente (top_family ausente o scores bajos/dispersos), escribe EXPLICITAMENTE en behavior_summary o analysis la frase 'Familia no determinada / no concluyente'.\n"
        "- NUNCA presentes un candidato como familia confirmada.\n\n"
        "Instrucciones de salida:\n"
        "- Responde SIEMPRE en formato JSON válido.\n"
        "- No incluyas markdown, comentarios ni texto fuera del JSON.\n"
        "- Usa esta estructura exacta:\n"
        "{\n"
        '  "analysis": "explicación técnica breve y precisa del resultado, justificando el veredicto del detector con sus evidencias",\n'
        '  "threat_level": "none | low | medium | high | critical",\n'
        '  "behavior_summary": "resumen técnico y conciso del comportamiento probable del archivo basado en los indicadores",\n'
        '  "recommended_actions": [\n'
        '    "acción operativa prioritaria para el equipo SOC",\n'
        '    "otras acciones concretas y ejecutables si son relevantes"\n'
        "  ]\n"
        "}\n\n"
        "Reglas adicionales:\n"
        "1) Usa únicamente los campos del bloque SCAN_SUMMARY.\n"
        "2) No inventes APIs, secciones, imports, scores ni métricas no presentes.\n"
        "3) Si un dato clave falta, indica explícitamente \"dato no disponible\".\n"
        "4) threat_level debe ser coherente con detector.verdict y detector.risk_level (ver REGLA CRITICA).\n"
        "5) Cita indicadores reales de evidences (source, score_raw, reasons) en tu analysis.\n"
        "6) Las recommended_actions deben ser concretas, técnicas y accionables para un equipo SOC.\n\n"
        f"SCAN_SUMMARY:\n{data_block}\n"
    )
