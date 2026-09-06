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

        build_llm_prompt (contrato F4.2) serializa {detector, evidences,
        family, legacy} tras la marca 'SCAN_SUMMARY:'. Se reconstruye un
        ScanResult mínimo con el veredicto autoritativo del detector.
        Si el bloque no está o no es JSON válido, devuelve dict vacío y el motor
        aplica su rama de incertidumbre (fail-soft, nunca lanza excepción,
        nunca inventa benignidad).
        """
        marker = "SCAN_SUMMARY:"
        idx = prompt.find(marker)
        if idx == -1:
            return {}
        candidate = prompt[idx + len(marker) :].strip()
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                if "detector" in parsed:
                    det = parsed.get("detector") or {}
                    leg = parsed.get("legacy") or {}
                    return {
                        "result": det.get("verdict"),
                        "risk_level": det.get("risk_level"),
                        "operational_status": det.get("operational_status"),
                        "confidence": det.get("confidence"),
                        "degraded": det.get("degraded"),
                        "coverage": det.get("correlation_score") if det.get("coverage") is None else det.get("coverage"),
                        "final_verdict": {"verdict": det.get("verdict")},
                        "evidences": parsed.get("evidences") or [],
                        "family_likelihoods": (parsed.get("family") or {}).get("family_likelihoods") or {},
                        "top_family": (parsed.get("family") or {}).get("top_family"),
                        "file_name": det.get("file_name"),
                        # Fallback legacy para prompts construidos con esquema antiguo
                        "label": leg.get("label"),
                        "score": leg.get("score"),
                        "details": {
                            "entropy": leg.get("entropy"),
                            "suspicious_imports": leg.get("suspicious_imports") or [],
                        },
                    }
                return {"label": parsed.get("label"), "score": parsed.get("score"),
                        "confidence": parsed.get("confidence"),
                        "details": parsed}
        except (ValueError, TypeError):
            logger.debug("TemplateExplainer: SCAN_SUMMARY no parseable, usando defaults")
        return {}

    def explain_from_scan_result(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Construye el objeto JSON de explicación forense estructurada en español.

        Lee el contrato ACTUAL (result/final_verdict/correlation/evidences)
        con fallback al esquema legacy (label/score/details) y a la capa
        operativa (operational_status/risk_level/yara_matches), porque
        ExplanationService puede recibir resultados de varias fuentes.
        El veredicto del detector es autoritativo: el template nunca lo
        contradice (Detector = autoridad, LLM = explicador).
        """
        final = scan_result.get("final_verdict")
        if not isinstance(final, dict):
            final = {}
        verdict = str(
            final.get("verdict") or scan_result.get("result")
            or scan_result.get("verdict") or scan_result.get("label") or "unknown"
        ).lower()
        operational_status = str(
            final.get("operational_status") or scan_result.get("operational_status", "")
        ).upper()
        risk_level = str(
            final.get("risk_level") or scan_result.get("risk_level", "")
        ).upper()
        _score = _as_float(scan_result.get("score"), default=-1.0)
        score: float = _score if isinstance(_score, (int, float)) else -1.0
        file_name = scan_result.get("file_name") or scan_result.get("file") or "archivo_analizado.bin"
        label = str(scan_result.get("label", verdict.upper() if verdict else "Unknown"))

        indicators: List[str] = []
        recommended_actions: List[str] = []

        # Indicadores estructurados del overlay de PE (capa Defender Extractor)
        overlay = scan_result.get("overlay_analysis") or {}
        if isinstance(overlay, dict) and overlay.get("overlay_detected"):
            _ratio = _as_float(overlay.get("overlay_ratio"), default=0.0)
            ratio = _ratio if isinstance(_ratio, (int, float)) else 0.0
            indicators.append(
                f"Se detectó un overlay que representa el {ratio * 100:.1f}% del tamaño total del archivo."
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
        _details = scan_result.get("details")
        details: Dict[str, Any] = _details if isinstance(_details, dict) else {}
        entropy = _as_float(details.get("entropy"), default=None)
        if entropy is not None and entropy >= 7.0:
            indicators.append(
                f"Entropía elevada ({entropy:.2f} bits/byte): sugiere bloqueos cifrados o comprimidos."
            )
        suspicious_imports = details.get("suspicious_imports")
        if isinstance(suspicious_imports, list) and suspicious_imports:
            shown = ", ".join(str(i) for i in suspicious_imports[:5])
            indicators.append(f"Imports sospechosos asociados a inyección/evasión: {shown}.")

        # Indicadores del Evidence Contract F2 (F4.2): el template es explicador,
        # el veredicto del detector es autoritativo y aquí solo se narra.
        contradiction_text: Optional[str] = None
        family_note = "Familia no determinada / no concluyente."
        raw_evs = scan_result.get("evidences")
        if isinstance(raw_evs, list):
            for ev in raw_evs:
                if not isinstance(ev, dict):
                    continue
                src = str(ev.get("source", ""))
                ev_verdict = str(ev.get("verdict", "")).lower()
                reasons = ev.get("reasons") or []
                r0 = str(reasons[0])[:200] if reasons else ""
                if ev_verdict in ("suspicious", "malicious"):
                    if src == "overlay" and r0:
                        indicators.append(f"Overlay forense ({ev_verdict}): {r0}.")
                    elif src == "pe_static" and r0:
                        indicators.append(f"PE estático ({ev_verdict}): {r0}.")
                    elif src == "heuristic" and r0:
                        indicators.append(f"Heurística ({ev_verdict}): {r0}.")
                    elif src == "dotnet" and r0:
                        indicators.append(f".NET ({ev_verdict}): {r0}.")
                    elif src == "yara" and r0:
                        indicators.append(f"YARA ({ev_verdict}): {r0}.")
                    elif r0:
                        indicators.append(f"{src} ({ev_verdict}): {r0}.")
            fv = final if isinstance(final, dict) else {}
            contradiction_text = fv.get("contradiction") or scan_result.get("contradiction")
            if contradiction_text:
                indicators.append(f"Contradicción entre fuentes: {str(contradiction_text)[:300]}.")
        _lik = scan_result.get("family_likelihoods")
        fam_lik: Dict[str, Any] = _lik if isinstance(_lik, dict) else {}
        top_fam = scan_result.get("top_family")
        if top_fam:
            family_note = f"Hipótesis de familia (no confirmada): {top_fam}."
        elif fam_lik:
            cands = ", ".join(f"{k}={v}" for k, v in list(fam_lik.items())[:6])
            family_note = (
                f"Candidatos no concluyentes ({cands}). Familia no determinada / no concluyente."
            )

        # Clasificación del veredicto: el detector manda (F4.2); el score ML es respaldo.
        is_suspicious_verdict = verdict in ("suspicious", "malicious")
        is_high = (
            verdict == "malicious"
            or operational_status in ("DANGEROUS", "CRITICAL")
            or risk_level in ("HIGH", "CRITICAL")
            or label.upper() in ("MALWARE", "MALICIOUS")
            or score >= 0.8
        )
        is_medium = (
            not is_high
            and (
                is_suspicious_verdict
                or operational_status == "SUSPICIOUS"
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
            # Coherencia F4.2: un veredicto suspicious del detector nunca es "none".
            if is_suspicious_verdict and threat_level == "none":
                threat_level = "medium"
            summary = (
                f"El archivo '{file_name}' no presenta indicadores maliciosos conocidos."
                if threat_level == "none"
                else f"El archivo '{file_name}' fue etiquetado como malicioso por el modelo "
                      "pero los indicadores estructurales son limitados."
            )
            if is_suspicious_verdict and threat_level == "medium":
                summary = (
                    f"El detector clasificó '{file_name}' como {verdict.upper()}; "
                    "los indicadores estructurales requieren supervisión. " + family_note
                )
            recommended_actions = (
                ["No se requieren acciones reactivas."]
                if threat_level == "none"
                else ["Re-verificar el archivo en sandbox antes de descartar la alerta."]
            )

        analysis = (
            "Análisis Forense Nativo (Offline):\n"
            f"- Archivo: {file_name}\n"
            f"- Veredicto del detector: {verdict.upper()}\n"
            + (f"- Veredicto ML: {label} (score={score:.4f})\n" if score >= 0 else "")
            + (f"- Estado Operativo: {operational_status}\n" if operational_status else "")
            + "- Hallazgos principales: "
            + (" ".join(indicators) if indicators else "Sin anomalías estructurales.")
            + f"\n- Familia: {family_note}"
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
