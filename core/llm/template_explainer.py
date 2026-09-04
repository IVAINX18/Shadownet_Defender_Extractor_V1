"""
core/llm/template_explainer.py — Generador nativo de explicaciones forenses sin IA.

Motor determinístico de última instancia en la cascada Tri-Fallover
(groq -> gemini -> template). No requiere red, API keys ni modelos:
construye la narrativa forense en español a partir de los indicadores
estructurados del ScanResult, emitiendo el mismo contrato JSON que los
clientes LLM (analysis, threat_level, behavior_summary, recommended_actions)
para que ExplanationService y el frontend traten todas las fuentes por igual.

Cumple la interfaz LLMClient vía generate(), aunque su camino natural es
explain_from_scan_result() — evita reconstruir el ScanResult desde el prompt.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("shadownet.llm.template")


class TemplateExplainer:
    """Generador determinístico de narrativas forenses basado en reglas del escaneo."""

    def generate(self, prompt: str, *, model: Optional[str] = None) -> str:
        """Adaptación a la interfaz LLMClient.

        El fallback real en ExplanationService invoca explain_from_scan_result()
        directamente con el dict original; este método existe para que el motor
        sea sustituible donde se espera un LLMClient y para pruebas. Con solo el
        prompt, recupera el bloque SCAN_SUMMARY embebido por build_llm_prompt()
        y lo traduce a un ScanResult mínimo.
        """
        scan_result = self._scan_result_from_prompt(prompt)
        return json.dumps(
            self.explain_from_scan_result(scan_result), ensure_ascii=False
        )

    @staticmethod
    def _scan_result_from_prompt(prompt: str) -> Dict[str, Any]:
        """Extrae el bloque JSON SCAN_SUMMARY del prompt para no perder indicadores.

        build_llm_prompt serializa el resumen tras la marca 'SCAN_SUMMARY:'.
        Si el bloque no está o no es JSON válido, devuelve dict vacío y el motor
        aplica su rama benigna por defecto (fail-soft, nunca lanza excepción).
        """
        marker = "SCAN_SUMMARY:"
        idx = prompt.find(marker)
        if idx == -1:
            return {}
        candidate = prompt[idx + len(marker) :].strip()
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return {"label": parsed.get("label"), "score": parsed.get("score"),
                        "confidence": parsed.get("confidence"),
                        "details": parsed}
        except (ValueError, TypeError):
            logger.debug("TemplateExplainer: SCAN_SUMMARY no parseable, usando defaults")
        return {}

    def explain_from_scan_result(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Construye el objeto JSON de explicación forense estructurada en español.

        Lee tanto el esquema del pipeline ML (label/score/details) como el de
        la capa operativa (operational_status/risk_level/yara_matches), porque
        ExplanationService puede recibir resultados de ambas fuentes.
        """
        operational_status = str(scan_result.get("operational_status", "")).upper()
        risk_level = str(scan_result.get("risk_level", "")).upper()
        score = _as_float(scan_result.get("score"), default=-1.0)
        file_name = scan_result.get("file_name") or scan_result.get("file") or "archivo_analizado.bin"
        label = str(scan_result.get("label", "Unknown"))

        indicators: List[str] = []
        recommended_actions: List[str] = []

        # Indicadores estructurados del overlay de PE (capa Defender Extractor)
        overlay = scan_result.get("overlay_analysis") or {}
        if isinstance(overlay, dict) and overlay.get("overlay_detected"):
            ratio = _as_float(overlay.get("overlay_ratio"), default=0.0) * 100
            indicators.append(
                f"Se detectó un overlay que representa el {ratio:.1f}% del tamaño total del archivo."
            )

        yara_matches = scan_result.get("yara_matches") or []
        if isinstance(yara_matches, list) and yara_matches:
            rules = ", ".join(
                y.get("rule_name", "") for y in yara_matches if isinstance(y, dict)
            )
            indicators.append(f"Coincidencia con reglas YARA de amenazas: {rules}.")

        if scan_result.get("obfuscator_detected"):
            name = scan_result.get("obfuscator_name", "desconocido")
            indicators.append(f"Empaquetador/Ofuscador detectado: {name}.")

        if scan_result.get("injection_detected"):
            indicators.append("Indicadores de inyección de código en procesos activos.")

        # Indicadores del pipeline ML (details: entropy, imports sospechosos)
        details = scan_result.get("details") if isinstance(scan_result.get("details"), dict) else {}
        entropy = _as_float(details.get("entropy"), default=None)
        if entropy is not None and entropy >= 7.0:
            indicators.append(
                f"Entropía elevada ({entropy:.2f} bits/byte): sugiere bloqueos cifrados o comprimidos."
            )
        suspicious_imports = details.get("suspicious_imports")
        if isinstance(suspicious_imports, list) and suspicious_imports:
            shown = ", ".join(str(i) for i in suspicious_imports[:5])
            indicators.append(f"Imports sospechosos asociados a inyección/evasión: {shown}.")

        # Clasificación del veredicto: capas operativas mandan; el score ML es respaldo.
        is_high = (
            operational_status in ("DANGEROUS", "CRITICAL")
            or risk_level in ("HIGH", "CRITICAL")
            or label.upper() in ("MALWARE", "MALICIOUS")
            or score >= 0.8
        )
        is_medium = (
            not is_high
            and (
                operational_status == "SUSPICIOUS"
                or risk_level == "MEDIUM"
                or 0.5 <= score < 0.8
            )
        )

        if is_high:
            threat_level = "critical" if (score >= 0.9 or risk_level == "CRITICAL") else "high"
            summary = (
                f"El archivo '{file_name}' presenta múltiples indicadores de alta peligrosidad"
                + (f" con una puntuación de riesgo de {score:.2f}." if score >= 0 else ".")
                + " Se recomienda aislamiento inmediato."
            )
            recommended_actions = [
                "Mover el archivo a cuarentena de inmediato.",
                "Bloquear la ejecución del proceso en el sistema.",
                "Revisar conexiones de red recientes generadas por este binario.",
            ]
        elif is_medium:
            threat_level = "medium"
            summary = (
                f"El archivo '{file_name}' muestra comportamientos anómalos o estructuras "
                "inusuales. Requiere supervisión."
            )
            recommended_actions = [
                "Evitar la ejecución con privilegios de administrador.",
                "Realizar un análisis dinámico en entorno aislado (sandbox).",
            ]
        else:
            threat_level = "low" if label.upper() in ("MALWARE", "MALICIOUS") else "none"
            summary = (
                f"El archivo '{file_name}' no presenta indicadores maliciosos conocidos."
                if threat_level == "none"
                else f"El archivo '{file_name}' fue etiquetado como malicioso por el modelo "
                     "pero los indicadores estructurales son limitados."
            )
            recommended_actions = (
                ["No se requieren acciones reactivas."]
                if threat_level == "none"
                else ["Re-verificar el archivo en sandbox antes de descartar la alerta."]
            )

        analysis = (
            "Análisis Forense Nativo (Offline):\n"
            f"- Archivo: {file_name}\n"
            + (f"- Veredicto ML: {label} (score={score:.4f})\n" if score >= 0 else "")
            + (f"- Estado Operativo: {operational_status}\n" if operational_status else "")
            + "- Hallazgos principales: "
            + (" ".join(indicators) if indicators else "Sin anomalías estructurales.")
        )

        return {
            "analysis": analysis,
            "threat_level": threat_level,
            "behavior_summary": summary,
            "recommended_actions": recommended_actions,
            "llm_inconsistent": False,
            "llm_confidence": 1.0,
            "mode": "template_offline",
        }


def _as_float(value: Any, default: Optional[float]) -> Optional[float]:
    """Convierte a float de forma segura; ante valores no numéricos devuelve default."""
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default
