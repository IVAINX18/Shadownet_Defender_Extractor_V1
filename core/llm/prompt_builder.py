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

    Reglas duras:
    - El modelo NO detecta malware, solo explica el resultado ML.
    - Debe ceñirse a los datos entregados.
    - Si un campo no existe, debe indicarlo explícitamente.
    """
    summary = extract_scan_summary(scan_result)
    data_block = json.dumps(summary, ensure_ascii=True, indent=2)

    return (
        "Rol: Eres un analista de ciberseguridad especializado en malware.\n"
        "Contexto obligatorio: ShadowNet Defender ya clasificó el archivo.\n"
        "Tu tarea NO es detectar malware; tu tarea es explicar el resultado con base en los datos.\n\n"
        "Reglas:\n"
        "1) Usa exclusivamente los campos del bloque SCAN_SUMMARY.\n"
        "2) No inventes APIs, secciones, imports ni métricas no presentes.\n"
        "3) Si falta información, escribe literalmente: 'dato no disponible'.\n"
        "4) Incluye razonamiento matemático simple con score y umbral 0.5.\n"
        "5) Responde SOLO en JSON válido con esta estructura exacta:\n"
        "{\n"
        '  "resumen_ejecutivo": "string",\n'
        '  "explicacion_tecnica": "string",\n'
        '  "justificacion_matematica": "string",\n'
        '  "indicadores_clave": ["string"],\n'
        '  "recomendaciones": ["string"]\n'
        "}\n\n"
        f"SCAN_SUMMARY:\n{data_block}\n"
    )

