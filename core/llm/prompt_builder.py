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


def extract_scan_summary(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrae únicamente campos permitidos para el prompt del LLM.

    Seguridad:
    - No se envía el archivo completo ni datos crudos.
    - Solo se usa resumen estructurado del JSON de escaneo.
    """
    details = scan_result.get("details", {})
    if not isinstance(details, dict):
        details = {}

    return {
        "label": scan_result.get("label", "Unknown"),
        "score": scan_result.get("score", -1.0),
        "confidence": scan_result.get("confidence", "Low"),
        "entropy": details.get("entropy"),
        "suspicious_imports": _safe_list(details.get("suspicious_imports")),
        "suspicious_sections": _safe_list(details.get("suspicious_sections")),
        "top_features": _safe_top_features(details.get("top_features")),
    }


def build_llm_prompt(scan_result: Dict[str, Any]) -> str:
    """
    Construye un prompt robusto para explicaciones técnicas sin alucinaciones.

    Objetivo:
    - Producir un informe estructurado en JSON para analistas SOC.

    Reglas duras:
    - El modelo NO detecta malware; solo explica el resultado ya calculado.
    - Debe ceñirse exclusivamente a los datos entregados.
    - Si un campo no existe, debe indicarlo explícitamente como \"dato no disponible\".
    """
    summary = extract_scan_summary(scan_result)
    data_block = json.dumps(summary, ensure_ascii=True, indent=2)

    return (
        "Rol: eres un analista de ciberseguridad especializado en malware.\n"
        "Contexto obligatorio: ShadowNet Defender ya clasificó el archivo y calculó un score de riesgo.\n"
        "Tu tarea NO es detectar malware; tu tarea es explicar el resultado con base en los datos de SCAN_SUMMARY.\n\n"
        "Instrucciones de salida:\n"
        "- Responde SIEMPRE en formato JSON válido.\n"
        "- No incluyas markdown, comentarios ni texto fuera del JSON.\n"
        "- Usa esta estructura exacta:\n"
        "{\n"
        '  "analysis": "explicación técnica breve y precisa del resultado, justificando por qué el archivo es malware o benigno",\n'
        '  "threat_level": "low | medium | high | critical",\n'
        '  "behavior_summary": "resumen técnico y conciso del comportamiento probable del archivo basado en los indicadores",\n'
        '  "recommended_actions": [\n'
        '    "acción operativa prioritaria para el equipo SOC",\n'
        '    "otras acciones concretas y ejecutables si son relevantes"\n'
        "  ]\n"
        "}\n\n"
        "Reglas adicionales:\n"
        "1) Usa únicamente los campos del bloque SCAN_SUMMARY.\n"
        "2) No inventes APIs, secciones, imports ni métricas no presentes.\n"
        "3) Si un dato clave falta, indica explícitamente \"dato no disponible\".\n"
        "4) Usa el umbral score >= 0.5 como indicativo de comportamiento malicioso y score < 0.5 como benigno.\n"
        "5) Asegúrate de que threat_level sea coherente con el score y la label.\n"
        "6) Las recommended_actions deben ser concretas, técnicas y accionables para un equipo SOC.\n\n"
        f"SCAN_SUMMARY:\n{data_block}\n"
    )
