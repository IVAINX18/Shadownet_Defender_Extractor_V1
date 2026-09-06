"""
core/engine.py — Motor central de ShadowNet Defender.

Orquesta el pipeline híbrido de detección en 4 fases:

    Fase 1 — YARA (Firmas Estáticas)
        Detección determinista instantánea de amenazas conocidas.
        Si hay coincidencia → MALWARE con score 1.0 (sin gastar ML).

    Fase 2 — Desempacado UPX
        Si el PE está empacado, se descomprime antes del análisis estático.
        Esto permite que el modelo ML vea el código malicioso real, no
        el descompresor de UPX que siempre parece benigno.

    Fase 3 — Extracción de Features + Inferencia ONNX
        Pipeline estático original: vector de 2381 dimensiones → modelo ONNX.

    Fase 4 — Elevación de Riesgo por Comportamiento Dinámico (opcional)
        Si el análisis estático devuelve BENIGN/SUSPICIOUS pero el proceso
        está activo mostrando comportamiento de malware, se eleva el riesgo.

Patrón Facade (Fachada):
    Esta clase es la "puerta de entrada" al sistema. Ni la CLI, ni la API,
    ni ningún otro módulo necesitan saber cómo funcionan internamente los
    extractores o el modelo ONNX. Solo llaman a `engine.scan_file(path)`
    y reciben un diccionario con el resultado.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np

from configs.settings import (
    HIGH_CONFIDENCE_THRESHOLD,
    MALWARE_THRESHOLD,
    MODEL_PATH,
    SCALER_PATH,
)
from core.errors import NonPEFileError
from core.overlay import OverlayAnalyzer
from core.heuristics import HeuristicRiskEngine
from core.dotnet import DotNetAnalyzer
from core.dotnet.il_analyzer import ILBehavioralAnalyzer
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
from core.correlation import CorrelationEngine
from extractors.extractor import PEFeatureExtractor
from models.inference import ShadowNetModel
from utils.logger import setup_logger
from utils.runtime_checks import validate_python_version

logger = setup_logger(__name__)


class ShadowNetEngine:
    """
    Motor central híbrido de ShadowNet Defender.

    El flujo de escaneo es:
        YARA → UPX Unpacking → Features ML → ONNX → (Dynamic Elevation)
    """

    def __init__(self) -> None:
        validate_python_version()

        # ── Módulo 1: Extractor de features ML ───────────────────────
        self.extractor = PEFeatureExtractor()

        # ── Módulo 2: Modelo ONNX ─────────────────────────────────────
        self.model: Optional[ShadowNetModel] = None
        self._load_model()

        # ── Módulo 3: Scanner YARA (Primera línea de defensa) ─────────
        self._yara_scanner = self._init_yara()

        # ── Módulo 4: Desempacador UPX ────────────────────────────────
        self._unpacker = self._init_unpacker()

        # ── Módulo 5: Analizador de Overlay (Anti-dropper) ───────────
        self._overlay_analyzer = OverlayAnalyzer()

        # ── Módulo 6: Motor Heurístico de Riesgo ─────────────────────
        self._risk_engine = HeuristicRiskEngine()

        # ── Módulo 7: Analizador .NET / CLR (Mejoras 1-8) ────────────
        self._dotnet_analyzer = DotNetAnalyzer()

        # ── Módulo 8: IL Behavioral Analyzer (Mejoras IL 1-18) ───────
        self._il_analyzer = ILBehavioralAnalyzer()

        # ── Módulo 9: BehavioralShield (Fase 7) ──────────────────────
        try:
            from core.dynamic.process_monitor import BehavioralShield
            self._behavioral_shield = BehavioralShield()
        except Exception as exc:
            logger.warning("BehavioralShield no disponible: %s", exc)
            self._behavioral_shield = None

        # ── Módulo 10: Correlation Engine (Fase 2 — Evidence Contract) ──
        self._correlation_engine = CorrelationEngine()

    # ------------------------------------------------------------------
    # API Pública
    # ------------------------------------------------------------------

    def scan_file(
        self,
        file_path: Union[str, Path],
        *,
        enable_behavioral: bool = False,
    ) -> Dict[str, Any]:
        """
        Escanea un archivo usando el pipeline hibrido completo.

        Args:
            file_path:         Ruta al archivo a analizar.
            enable_behavioral: Si True, ejecuta la Fase 8 (BehavioralShield).
                               Por defecto False para preservar comportamiento V3
                               y no introducir dependencias de psutil en CI.

        Returns:
            Diccionario con label, score, status, confidence, details,
            yara_matches, was_unpacked, operational_status, behavioral_analysis, etc.
        """
        import concurrent.futures
        from configs.settings import ANALYSIS_TIMEOUT_SECONDS

        file_path = Path(file_path)

        # Watchdog global: el pipeline completo no puede superar ANALYSIS_TIMEOUT_SECONDS
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                self._scan_file_internal, file_path, enable_behavioral
            )
            try:
                return future.result(timeout=ANALYSIS_TIMEOUT_SECONDS)
            except concurrent.futures.TimeoutError:
                logger.error(
                    "Análisis de %s superó el timeout de %ds → SUSPICIOUS",
                    file_path.name,
                    ANALYSIS_TIMEOUT_SECONDS,
                )
                return {
                    "file": str(file_path),
                    "status": "timeout",
                    "score": -1.0,
                    "label": "UNKNOWN",
                    "confidence": "Low",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "details": {"reason": "analysis_timeout"},
                    "yara_matches": [],
                    "was_unpacked": False,
                    "detection_phases": [],
                    "operational_status": "SUSPICIOUS",
                    "risk_level": "MEDIUM",
                    "risk_score": 0,
                    "overlay_analysis": {},
                    "heuristic_assessment": {},
                    "is_dotnet": False,
                    "clr_version": "",
                    "assembly_name": "",
                    "obfuscator_detected": False,
                    "obfuscator_name": "",
                    "embedded_assemblies_count": 0,
                    "reflection_usage": False,
                    "dynamic_loading_detected": False,
                    "dotnet_risk_score": 0,
                    "dotnet_risk_level": "LOW",
                    "dotnet_analysis": {},
                    "il_behavioral": {},
                    "dotnet_threat_score": 0,
                    "dotnet_threat_level": "LOW",
                    "family_likelihoods": {},
                    "top_family": "",
                    "injection_detected": False,
                    "persistence_detected": False,
                    "networking_detected": False,
                    "credential_theft_detected": False,
                    "worm_behavior_detected": False,
                    "rat_detected": False,
                    "stealer_detected": False,
                    "behavioral_analysis": None,
                    "scan_time_ms": ANALYSIS_TIMEOUT_SECONDS * 1000,
                }

    def _scan_file_internal(
        self, file_path: Path, enable_behavioral: bool = False
    ) -> Dict[str, Any]:
        """Pipeline interno de escaneo (ejecutado con watchdog en scan_file).

        Args:
            file_path:         Ruta al archivo.
            enable_behavioral: Si True, ejecuta Fase 8 BehavioralShield.
                               Si False (default), behavioral_analysis=None.
        """
        start_time = time.time()

        result: Dict[str, Any] = {
            "file": str(file_path),
            "status": "error",
            "score": -1.0,
            "label": "Unknown",
            "confidence": "Low",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "details": {},
            "yara_matches": [],
            "was_unpacked": False,
            "detection_phases": [],
            # Campos nuevos — compatibles con SOREL-20M (no tocan el vector)
            "operational_status": "SUSPICIOUS",  # T-03: nunca UNKNOWN
            "risk_level": "LOW",
            "risk_score": 0,
            "overlay_analysis": {},
            "heuristic_assessment": {},
            # Telemetría .NET extendida (Mejora 8) — valores por defecto
            "is_dotnet": False,
            "clr_version": "",
            "assembly_name": "",
            "obfuscator_detected": False,
            "obfuscator_name": "",
            "embedded_assemblies_count": 0,
            "reflection_usage": False,
            "dynamic_loading_detected": False,
            "dotnet_risk_score": 0,
            "dotnet_risk_level": "LOW",
            "dotnet_analysis": {},
            # Telemetría IL Behavioral (M16) — valores por defecto
            "il_behavioral": {},
            "dotnet_threat_score": 0,
            "dotnet_threat_level": "LOW",
            "family_likelihoods": {},
            "top_family": "",
            "injection_detected": False,
            "persistence_detected": False,
            "networking_detected": False,
            "credential_theft_detected": False,
            "worm_behavior_detected": False,
            "rat_detected": False,
            "stealer_detected": False,
            # ── BehavioralShield (Fase 7) ─────────────────────────────
            "behavioral_analysis": None,
        }

        if not file_path.exists():
            result["error"] = "File not found"
            return result

        # ── FASE 1: YARA ──────────────────────────────────────────────
        yara_result = self._run_yara_phase(file_path, result)
        if yara_result is not None:
            # YARA confirmó malware → retornar inmediatamente
            elapsed = time.time() - start_time
            yara_result["scan_time_ms"] = round(elapsed * 1000, 2)
            return yara_result

        # ── FASE 2: Desempacado UPX ───────────────────────────────────
        analysis_path = self._run_unpack_phase(file_path, result)

        # ── FASE 3: Extracción ML + Inferencia ONNX ───────────────────
        self._run_ml_phase(analysis_path, result)

        # ── FASE 4: Análisis Forense de Overlay + Heurística ─────────
        # Se ejecuta siempre, independientemente del resultado ML.
        # Usa el archivo ORIGINAL (no el desempacado) para detectar
        # overlays cifrados que UPX no puede desempacar.
        try:
            self._run_overlay_phase(file_path, result)
        except Exception as _exc:
            logger.error("Error en fase overlay para %s: %s", file_path.name, _exc)
            result["details"]["overlay_phase_error"] = True

        # ── FASE 5: Análisis .NET / CLR (Mejoras 1-8) ────────────────
        # Se ejecuta siempre que el archivo sea PE válido.
        # Detecta CLR header, ofuscadores, assemblies embebidos, IL sospechoso.
        # Pasa el dotnet_report al risk engine para ajustar pesos (Mejora 2).
        try:
            self._run_dotnet_phase(file_path, result)
        except Exception as _exc:
            logger.error("Error en fase dotnet para %s: %s", file_path.name, _exc)
            result["details"]["dotnet_phase_error"] = True

        # ── FASE 6: IL Behavioral Analysis ────────────────────────────
        # Se ejecuta solo si el archivo es .NET (detectado en Fase 5).
        # Analiza semánticamente el código IL para identificar RATs,
        # Loaders, Stealers, Worms, Downloaders y Droppers.
        # Eleva el operational_status si dotnet_threat_score ≥ umbral.
        try:
            self._run_il_phase(file_path, result)
        except Exception as _exc:
            logger.error("Error en fase IL para %s: %s", file_path.name, _exc)
            result["details"]["il_phase_error"] = True

        # Fase 8: BehavioralShield (opt-in via enable_behavioral)
        # Solo se ejecuta si el flag esta activo para no impactar el pipeline
        # por defecto y no introducir dependencias de psutil en CI.
        if enable_behavioral:
            self._run_behavioral_phase(file_path, result)
        # Si el flag esta inactivo, behavioral_analysis permanece None (ya en el dict)

        # ── FASE 9: Evidence Contract + Correlation Engine (Fases 1-2) ─
        # Construye evidencias independientes de cada capa y correlaciona
        # sin "last writer wins". Preserva score ML intacto.
        try:
            result = self._run_correlation_phase(file_path, result)
        except Exception as _exc:
            logger.error("Error en fase de correlacion para %s: %s", file_path.name, _exc)
            result["details"]["correlation_phase_error"] = str(_exc)

        # ── Limpieza del archivo desempacado temporal ─────────────────
        if result["was_unpacked"] and analysis_path != file_path:
            try:
                analysis_path.unlink(missing_ok=True)
                if analysis_path.parent.exists():
                    try:
                        analysis_path.parent.rmdir()
                    except OSError:
                        pass
            except Exception:
                pass

        elapsed = time.time() - start_time
        result["scan_time_ms"] = round(elapsed * 1000, 2)
        logger.info(
            "Escaneo completo: %s | label=%s | score=%.4f | operational=%s | "
            "risk=%s(%d) | phases=%s | time=%.0fms",
            file_path.name,
            result["label"],
            result.get("score", -1.0),
            result["operational_status"],
            result["risk_level"],
            result["risk_score"],
            result["detection_phases"],
            elapsed * 1000,
        )
        return result

    # ------------------------------------------------------------------
    # Fases del Pipeline
    # ------------------------------------------------------------------

    def _run_yara_phase(
        self, file_path: Path, result: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Fase 1: Escanear con YARA.

        Returns:
            Un resultado completo de MALWARE si YARA detectó algo, o None
            para continuar con las siguientes fases del pipeline.
        """
        if self._yara_scanner is None or not self._yara_scanner.is_available:
            return None

        try:
            yara_scan = self._yara_scanner.scan(file_path)
            result["detection_phases"].append("YARA")
            # Propagar estado YARA para Evidence Contract (F3): timeout => DEGRADED, error => UNAVAILABLE no silencioso
            if yara_scan.error:
                if "timeout" in yara_scan.error.lower():
                    result["details"]["yara_degraded"] = yara_scan.error
                    result["yara_status"] = "degraded"
                    logger.warning("YARA degraded (timeout) para %s: %s", file_path.name, yara_scan.error)
                else:
                    result["details"]["yara_error"] = yara_scan.error

            if yara_scan.has_matches:
                threat_names = yara_scan.threat_names
                categories = yara_scan.categories

                # Calcular SHA-256 para verificar contra whitelist de software legitimo
                try:
                    sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
                except Exception:
                    sha256 = ""

                # Si el archivo esta en whitelist, degradar a SUSPICIOUS en lugar de DANGEROUS
                if sha256 and self._yara_scanner.is_whitelisted(sha256, yara_scan.matches):
                    logger.info(
                        "YARA whitelist: %s degradado de DANGEROUS a SUSPICIOUS "
                        "(reglas: %s | sha256: %s...)",
                        file_path.name,
                        threat_names,
                        sha256[:16],
                    )
                    # No retornar early: continuar el pipeline con status SUSPICIOUS
                    # para que el resto de las fases también analicen el archivo.
                    result["yara_matches"] = [
                        {
                            "rule": m.rule_name,
                            "category": m.category,
                            "tags": m.tags,
                            "meta": m.meta,
                        }
                        for m in yara_scan.matches
                    ]
                    result["operational_status"] = "SUSPICIOUS"
                    result["risk_level"] = "MEDIUM"
                    result["heuristic_assessment"] = {
                        "whitelist_hit": True,
                        "whitelisted": True,
                    }
                    result["details"]["whitelist_hit"] = True
                    result["details"]["threat_names"] = threat_names
                    result["detection_phases"].append("YARA_WHITELISTED")
                    # Continuar con fases ML/overlay para analisis completo
                    return None

                logger.warning(
                    "YARA: Amenaza confirmada en %s — Reglas: %s | Categorías: %s",
                    file_path.name,
                    threat_names,
                    categories,
                )

                # Construir resultado de MALWARE con score máximo — T-03: DANGEROUS
                yara_result = dict(result)
                yara_result.update({
                    "status": "detected",
                    "label": "MALWARE",
                    "score": 1.0,
                    "confidence": "High",
                    "operational_status": "DANGEROUS",
                    "detection_phases": ["YARA"],
                    "yara_matches": [
                        {
                            "rule": m.rule_name,
                            "category": m.category,
                            "tags": m.tags,
                            "meta": m.meta,
                        }
                        for m in yara_scan.matches
                    ],
                    "details": {
                        "threat_names": threat_names,
                        "threat_categories": categories,
                        "detection_method": "YARA signature",
                        "yara_scan_time_ms": round(yara_scan.scan_time_ms, 2),
                    },
                })
                return yara_result
        except Exception as exc:
            logger.error("Error en fase YARA para %s: %s", file_path.name, exc)

        return None

    def _run_unpack_phase(self, file_path: Path, result: Dict[str, Any]) -> Path:
        """
        Fase 2: Intentar desempacar si el archivo está empacado con UPX.

        Returns:
            La ruta del archivo a analizar (desempacado u original).
        """
        if self._unpacker is None:
            return file_path

        try:
            # Leer los bytes para detectar UPX sin abrir el archivo dos veces
            raw_data = file_path.read_bytes()

            if self._unpacker.is_packed(raw_data):
                result["detection_phases"].append("UPX_DETECT")
                unpack_result = self._unpacker.try_unpack(file_path)

                if unpack_result.was_unpacked:
                    result["was_unpacked"] = True
                    result["detection_phases"].append("UPX_UNPACK")
                    logger.info(
                        "Analizando PE desempacado: %s → %s",
                        file_path.name,
                        unpack_result.unpacked_path.name,
                    )
                    return unpack_result.unpacked_path
        except Exception as exc:
            logger.error("Error en fase de desempacado para %s: %s", file_path.name, exc)

        return file_path

    def _run_ml_phase(self, analysis_path: Path, result: Dict[str, Any]) -> None:
        """
        Fase 3: Extracción de features + inferencia ONNX.

        Modifica result en su lugar con el label, score y confidence.
        """
        try:
            logger.info("Extrayendo features de: %s", analysis_path.name)
            result["detection_phases"].append("ML_STATIC")

            # T-04: envolver extract() con timeout configurable
            import concurrent.futures as _cf
            from configs.settings import EXTRACTOR_TIMEOUT_SECONDS
            with _cf.ThreadPoolExecutor(max_workers=1) as _executor:
                _future = _executor.submit(self.extractor.extract, str(analysis_path))
                try:
                    features = _future.result(timeout=EXTRACTOR_TIMEOUT_SECONDS)
                except _cf.TimeoutError:
                    logger.warning(
                        "Extractor timeout (%ds) para %s → SUSPICIOUS",
                        EXTRACTOR_TIMEOUT_SECONDS, analysis_path.name,
                    )
                    result["operational_status"] = "SUSPICIOUS"
                    result["details"]["degradation_reason"] = "extractor_timeout"
                    result["label"] = "SUSPICIOUS"
                    return
            
            # Integrar diagnósticos de auditoría y packing en los detalles del resultado (Mejora 6)
            if hasattr(self.extractor, "last_diagnostics") and self.extractor.last_diagnostics:
                result["details"].update(self.extractor.last_diagnostics)

            # 2.3 — Detectar modo RAW_FALLBACK del extractor
            if hasattr(self.extractor, "last_diagnostics") and self.extractor.last_diagnostics:
                _diag = self.extractor.last_diagnostics
                if _diag.get("raw_fallback") or (
                    isinstance(_diag.get("diagnostics"), dict)
                    and _diag["diagnostics"].get("raw_fallback")
                ):
                    if "diagnostics" not in result["details"]:
                        result["details"]["diagnostics"] = {}
                    result["details"]["diagnostics"]["extraction_mode"] = "RAW_FALLBACK"
                    result["confidence"] = "Low"
                    logger.info(
                        "Extractor en modo RAW_FALLBACK para %s → confidence=Low",
                        analysis_path.name,
                    )

            if self.model:
                try:
                    score = self.model.predict(features)
                except Exception as onnx_exc:
                    # 2.1 — Fallo ONNX → UNKNOWN / SUSPICIOUS
                    logger.error(
                        "Error ONNX en inferencia de %s: %s", analysis_path.name, onnx_exc
                    )
                    result["label"] = "UNKNOWN"
                    result["score"] = -1.0
                    result["operational_status"] = "SUSPICIOUS"
                    result["details"]["ml_phase_error"] = True
                    return

                result["score"] = round(score, 4)

                # Labeling
                if score >= MALWARE_THRESHOLD:
                    result["label"] = "MALWARE"
                    result["status"] = "detected"
                else:
                    result["label"] = "BENIGN"
                    result["status"] = "clean"

                # Nivel de confianza
                if score > HIGH_CONFIDENCE_THRESHOLD or score < (1.0 - HIGH_CONFIDENCE_THRESHOLD):
                    result["confidence"] = "High"
                elif score > 0.6 or score < 0.4:
                    result["confidence"] = "Medium"
                else:
                    result["confidence"] = "Low"
            else:
                result["error"] = "Model not loaded"
                logger.error("Intento de escaneo sin modelo cargado.")

        except NonPEFileError:
            result["status"] = "not_supported"
            result["label"] = "NOT_PE"
            result["error"] = "File is not a valid PE executable"
            logger.warning("Archivo no-PE omitido: %s", analysis_path)
            # 2.2 — Si el archivo tiene extensión ejecutable, elevar a SUSPICIOUS
            if analysis_path.suffix.lower() in (".exe", ".dll", ".sys"):
                result["operational_status"] = "SUSPICIOUS"
                logger.warning(
                    "NonPEFileError en archivo con extensión ejecutable (%s) → SUSPICIOUS",
                    analysis_path.suffix,
                )

        except Exception as exc:
            # 2.1 — Fallo de ONNX → UNKNOWN / SUSPICIOUS
            logger.error("Fallo en fase ML para %s: %s", analysis_path, exc)
            result["label"] = "UNKNOWN"
            result["score"] = -1.0
            result["operational_status"] = "SUSPICIOUS"
            result["details"]["ml_phase_error"] = True
            result["error"] = str(exc)

    def _run_overlay_phase(self, file_path: Path, result: Dict[str, Any]) -> None:
        """
        Fase 4 — Análisis forense de overlay + YARA sobre overlay + heurística.

        Se ejecuta SIEMPRE sobre el archivo original, independientemente
        del resultado del modelo ML. Es la capa que detecta droppers y
        loaders con payloads cifrados en overlay.

        No modifica 'label', 'score' ni 'confidence' del modelo ONNX.
        Solo agrega: overlay_analysis, heuristic_assessment,
        operational_status, risk_level, risk_score.
        """
        result["detection_phases"].append("OVERLAY_FORENSICS")
        try:
            raw_data = file_path.read_bytes()

            # Recuperar el objeto PE del extractor si existe en caché
            # (El extractor ya habrá corrido en la fase ML)
            pe_obj = None  # No disponible aquí; OverlayAnalyzer parsea el header por su cuenta

            # 4a. Análisis del overlay
            overlay_report = self._overlay_analyzer.analyze(raw_data, pe_obj)

            # 4b. YARA sobre el overlay (si hay overlay y YARA disponible)
            if overlay_report.overlay_present and self._yara_scanner and self._yara_scanner.is_available:
                overlay_bytes = raw_data[overlay_report.overlay_offset:]

                # Escaneo sobre el overlay completo (limitado a 20 MB por seguridad)
                yara_overlay = self._yara_scanner.scan_bytes(
                    overlay_bytes[:20 * 1024 * 1024],
                    label=f"{file_path.name}::overlay",
                )
                if yara_overlay.has_matches:
                    overlay_report.overlay_yara_hits = yara_overlay.threat_names
                    logger.warning(
                        "YARA: Amenaza en OVERLAY de %s — Reglas: %s | Categorías: %s",
                        file_path.name,
                        yara_overlay.threat_names,
                        yara_overlay.categories,
                    )

                # 4c. YARA sobre cada PE embebido encontrado
                for emb in overlay_report.embedded_pe_details:
                    emb_start = overlay_report.overlay_offset + emb.offset_in_overlay
                    emb_bytes = raw_data[emb_start:emb_start + min(emb.estimated_size, 5 * 1024 * 1024)]
                    yara_emb = self._yara_scanner.scan_bytes(
                        emb_bytes,
                        label=f"{file_path.name}::embedded_pe@{emb.offset_in_overlay}",
                    )
                    if yara_emb.has_matches:
                        overlay_report.embedded_pe_yara_hits.extend(yara_emb.threat_names)
                        logger.warning(
                            "YARA: Amenaza en PE EMBEBIDO de %s @ overlay+%d — Reglas: %s",
                            file_path.name,
                            emb.offset_in_overlay,
                            yara_emb.threat_names,
                        )

            # 4d. Scoring heurístico
            packer_indicators = {}
            if hasattr(self.extractor, "last_diagnostics") and self.extractor.last_diagnostics:
                packer_indicators = (
                    self.extractor.last_diagnostics
                    .get("diagnostics", {})
                    .get("packer_indicators", {})
                )

            ml_score = result.get("score", None)
            if ml_score is not None and ml_score < 0:
                ml_score = None  # Score -1 = no disponible

            risk = self._risk_engine.assess(
                overlay_report=overlay_report,
                packer_indicators=packer_indicators,
                ml_score=ml_score,
            )

            # 4e. Actualizar resultado (NO se modifica label/score/confidence del ML)
            result["overlay_analysis"] = overlay_report.to_dict()
            result["heuristic_assessment"] = risk.to_dict()
            result["operational_status"] = risk.operational_status
            result["risk_level"] = risk.risk_level
            result["risk_score"] = risk.risk_score

            # Si YARA encontró algo en el overlay, actualizar yara_matches del resultado
            if overlay_report.overlay_yara_hits or overlay_report.embedded_pe_yara_hits:
                all_yara_hits = (
                    result.get("yara_matches", []) +
                    overlay_report.overlay_yara_hits +
                    overlay_report.embedded_pe_yara_hits
                )
                result["yara_matches"] = list(set(all_yara_hits))
                # Si YARA confirma malware en overlay, elevar status sin cambiar label ML
                if result["status"] == "clean":
                    result["status"] = "suspicious"

            # Agregar telemetría forense a details
            result["details"]["overlay_forensics"] = {
                "overlay_present": overlay_report.overlay_present,
                "overlay_ratio": round(overlay_report.overlay_ratio, 4),
                "overlay_entropy": round(overlay_report.overlay_entropy, 4),
                "global_entropy": round(overlay_report.global_entropy, 4),
                "embedded_pe_detected": overlay_report.embedded_pe_detected,
                "embedded_pe_count": overlay_report.embedded_pe_count,
                "is_known_installer": overlay_report.is_known_installer,
                "installer_type": overlay_report.installer_type,
                "risk_score": risk.risk_score,
                "risk_level": risk.risk_level,
                "operational_status": risk.operational_status,
            }

        except Exception as exc:
            logger.error("Error en fase de overlay/heurística para %s: %s", file_path.name, exc)

    def _run_dotnet_phase(self, file_path: Path, result: Dict[str, Any]) -> None:
        """
        Fase 5 — Análisis .NET/CLR.

        Detecta si el archivo es un ensamblado .NET y, si es así:
            - Extrae CLR Header, metadata streams, assembly info.
            - Detecta ofuscadores conocidos.
            - Detecta assemblies/PEs embebidos en recursos.
            - Detecta indicadores IL sospechosos.
            - Genera dotnet_risk_score y dotnet_risk_level.
            - Re-evalúa la heurística con pesos .NET (Mejora 2).

        No modifica label, score ni confidence del modelo ONNX.
        """
        if result.get("label") == "NOT_PE":
            return

        result["detection_phases"].append("DOTNET_ANALYSIS")
        try:
            raw_data = file_path.read_bytes()
            dotnet_report = self._dotnet_analyzer.analyze(raw_data)

            if not dotnet_report.is_dotnet:
                return

            # ── Poblar telemetría extendida (Mejora 8) ─────────────────
            result["is_dotnet"] = True
            result["clr_version"] = dotnet_report.assembly_info.clr_version
            result["assembly_name"] = dotnet_report.assembly_info.assembly_name
            result["obfuscator_detected"] = dotnet_report.obfuscator.detected
            result["obfuscator_name"] = dotnet_report.obfuscator.name
            result["embedded_assemblies_count"] = dotnet_report.embedded.embedded_assemblies_count
            result["reflection_usage"] = dotnet_report.suspicious_il.reflection_usage
            result["dynamic_loading_detected"] = dotnet_report.suspicious_il.dynamic_loading_detected
            result["dotnet_risk_score"] = dotnet_report.risk_profile.dotnet_risk_score
            result["dotnet_risk_level"] = dotnet_report.risk_profile.dotnet_risk_level
            result["dotnet_analysis"] = dotnet_report.to_dict()

            logger.info(
                "Fase .NET: assembly=%s clr=%s obfuscator=%s dotnet_risk=%s(%d)",
                result["assembly_name"],
                result["clr_version"],
                result["obfuscator_name"] or "none",
                result["dotnet_risk_level"],
                result["dotnet_risk_score"],
            )

            # ── Re-evaluar heurística con contexto .NET (Mejora 2) ─────
            if result.get("heuristic_assessment"):
                try:
                    overlay_report = self._overlay_analyzer.analyze(raw_data, None)
                    packer_indicators = (
                        result.get("details", {})
                        .get("diagnostics", {})
                        .get("packer_indicators", {})
                    )
                    ml_score = result.get("score")
                    if ml_score is not None and ml_score < 0:
                        ml_score = None

                    risk = self._risk_engine.assess(
                        overlay_report=overlay_report,
                        packer_indicators=packer_indicators,
                        ml_score=ml_score,
                        dotnet_report=dotnet_report,
                    )

                    result["heuristic_assessment"] = risk.to_dict()
                    result["operational_status"] = risk.operational_status
                    result["risk_level"] = risk.risk_level
                    result["risk_score"] = risk.risk_score

                    if "overlay_forensics" in result.get("details", {}):
                        result["details"]["overlay_forensics"].update({
                            "risk_score": risk.risk_score,
                            "risk_level": risk.risk_level,
                            "operational_status": risk.operational_status,
                            "dotnet_context_applied": True,
                        })

                    logger.info(
                        "Heurística re-evaluada con contexto .NET: "
                        "score=%d level=%s operational=%s",
                        risk.risk_score, risk.risk_level, risk.operational_status,
                    )
                except Exception as e:
                    logger.warning("No se pudo re-evaluar heurística en contexto .NET: %s", e)

            # ── Elevar status si dotnet_risk es HIGH o CRITICAL ────────
            if dotnet_report.risk_profile.dotnet_risk_level in ("HIGH", "CRITICAL"):
                if result.get("operational_status") == "CLEAN":
                    result["operational_status"] = "SUSPICIOUS"
                    logger.info(
                        "Operational status elevado a SUSPICIOUS por dotnet_risk=%s",
                        dotnet_report.risk_profile.dotnet_risk_level,
                    )

        except Exception as exc:
            logger.error("Error en fase .NET para %s: %s", file_path.name, exc)

    def _run_il_phase(self, file_path: Path, result: Dict[str, Any]) -> None:
        """
        Fase 6 — IL Behavioral Analysis.

        Solo se ejecuta si el archivo fue identificado como .NET en Fase 5.
        Analiza semánticamente el IL buscando comportamientos maliciosos
        típicos de RATs, Loaders, Stealers, Worms y Downloaders.

        M15 — Integración con Operational Status:
            Si dotnet_threat_score >= 50 (HIGH) y operational_status == CLEAN
            → eleva a SUSPICIOUS.
            Si dotnet_threat_score >= 75 (CRITICAL)
            → eleva a DANGEROUS independientemente del ML score.

        No modifica label, score ni confidence del modelo ONNX.
        """
        # Solo ejecutar en archivos .NET detectados
        if not result.get("is_dotnet", False):
            return

        result["detection_phases"].append("IL_BEHAVIORAL")
        try:
            raw_data = file_path.read_bytes()
            il_report = self._il_analyzer.analyze(raw_data)

            # ── Poblar telemetría IL (M16) ─────────────────────────────
            il_dict = il_report.to_dict()
            result["il_behavioral"] = il_dict
            result["dotnet_threat_score"] = il_report.dotnet_threat_score
            result["dotnet_threat_level"] = il_report.dotnet_threat_level
            result["family_likelihoods"] = il_report.family_likelihoods
            result["top_family"] = il_report.top_family
            result["injection_detected"] = il_report.injection.detected
            result["persistence_detected"] = il_report.persistence.detected
            result["networking_detected"] = il_report.networking.detected
            result["credential_theft_detected"] = il_report.credential_theft.detected
            result["worm_behavior_detected"] = il_report.worm.detected
            result["rat_detected"] = il_report.rat.detected
            result["stealer_detected"] = il_report.stealer.detected
            # Actualizar campos ya existentes de la fase dotnet
            result["reflection_usage"] = il_report.reflection.detected
            result["dynamic_loading_detected"] = il_report.dynamic_loading.detected

            # ── M15: Elevar Operational Status según threat_score ──────
            threat_score = il_report.dotnet_threat_score
            current_status = result.get("operational_status", "CLEAN")

            if threat_score >= 75:
                # CRITICAL — forzar DANGEROUS sin importar ML
                result["operational_status"] = "DANGEROUS"
                logger.warning(
                    "IL: dotnet_threat_score=%d (CRITICAL) → DANGEROUS | "
                    "top_family=%s | file=%s",
                    threat_score,
                    il_report.top_family or "unknown",
                    file_path.name,
                )
            elif threat_score >= 50 and current_status in ("CLEAN", "UNKNOWN"):
                result["operational_status"] = "SUSPICIOUS"
                logger.warning(
                    "IL: dotnet_threat_score=%d (HIGH) → SUSPICIOUS | "
                    "top_family=%s | file=%s",
                    threat_score,
                    il_report.top_family or "unknown",
                    file_path.name,
                )
            elif threat_score >= 25 and current_status == "CLEAN":
                result["operational_status"] = "SUSPICIOUS"
                logger.info(
                    "IL: dotnet_threat_score=%d (MEDIUM) → SUSPICIOUS | file=%s",
                    threat_score,
                    file_path.name,
                )

            # ── Añadir resumen IL a details ────────────────────────────
            result["details"]["il_behavioral"] = {
                "threat_score": threat_score,
                "threat_level": il_report.dotnet_threat_level,
                "top_family": il_report.top_family,
                "indicators_fired": len(il_report.all_evidence),
                "evidence_sample": il_report.all_evidence[:10],
                "family_likelihoods": il_report.family_likelihoods,
            }

            logger.info(
                "Fase IL completa: %s | threat=%d (%s) | family=%s | "
                "operational=%s | indicators=%d",
                file_path.name,
                threat_score,
                il_report.dotnet_threat_level,
                il_report.top_family or "none",
                result["operational_status"],
                len(il_report.all_evidence),
            )

        except Exception as exc:
            logger.error("Error en fase IL para %s: %s", file_path.name, exc)

    def _run_correlation_phase(self, file_path: Path, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fase 9 — Correlation Engine (Evidence Contract).

        Construye evidencias independientes de cada capa y correlaciona
        sin "last writer wins". Preserva score ML intacto.
        """
        from core.evidence import EvidenceSource, EvidenceVerdict, Severity, OperationalStatus

        # ── Recolectar datos para evidencias ──────────────────────────
        ml_score = result.get("score", -1.0)
        # Distinguir error ML (score -1) vs benign 0.0
        if ml_score is None or ml_score < 0:
            ml_status = EvidenceStatus.ERROR
            ml_err = result.get("details", {}).get("ml_phase_error") and "ml_phase_error" or "ML unavailable"
        elif result.get("label") == "NOT_PE":
            ml_status = EvidenceStatus.ERROR
            ml_err = "NOT_PE"
        else:
            ml_status = EvidenceStatus.OK
            ml_err = None

        yara_status = EvidenceStatus.OK
        yara_err = None
        if self._yara_scanner is None or not getattr(self._yara_scanner, "is_available", False):
            yara_status = EvidenceStatus.UNAVAILABLE
            yara_err = "YARA unavailable (yara-python no instalado)"

        packer_indicators: Dict[str, Any] = {}
        if hasattr(self.extractor, "last_diagnostics") and self.extractor.last_diagnostics:
            packer_indicators = (
                self.extractor.last_diagnostics.get("diagnostics", {}).get("packer_indicators", {}) or {}
            )

        # Heuristic assessment dict -> RiskAssessment-like
        heuristic_dict = result.get("heuristic_assessment", {})
        overlay_dict = result.get("overlay_analysis", {})
        dotnet_dict = result.get("dotnet_analysis", {})
        il_dict = result.get("il_behavioral", {})

        # ── Construir evidencias ──────────────────────────────────────
        evidences: List[Evidence] = []

        # ML evidencia (preserva score intacto)
        if ml_status == EvidenceStatus.ERROR:
            evidences.append(ml_evidence(score=0.0, label="UNKNOWN", status=ml_status, error=ml_err))
            # Ajustar score a None manualmente para distinguir error de 0.0
            evidences[-1].score = None
            evidences[-1].verdict = EvidenceVerdict.UNKNOWN
        else:
            evidences.append(ml_evidence(score=float(ml_score) if ml_score is not None else 0.0, label=result.get("label", "UNKNOWN"), confidence=result.get("confidence", "Low"), status=ml_status, error=ml_err))

        # YARA evidencia (F3: distingue OK/DEGRADED/UNAVAILABLE)
        yara_matches = result.get("yara_matches", [])
        has_yara = bool(yara_matches)
        # Detectar DEGRADED por timeout guardado en details
        yara_degraded = result.get("details", {}).get("yara_degraded") or result.get("yara_status") == "degraded"
        if yara_degraded:
            evidences.append(yara_evidence(has_matches=False, status=EvidenceStatus.DEGRADED, degraded_reason=str(result.get("details", {}).get("yara_degraded") or "YARA timeout")))
        elif yara_status == EvidenceStatus.UNAVAILABLE:
            evidences.append(yara_evidence(has_matches=False, status=yara_status, degraded_reason=yara_err))
        else:
            threat_names = []
            for m in yara_matches:
                if isinstance(m, dict):
                    threat_names.append(m.get("rule", str(m)))
                elif isinstance(m, str):
                    threat_names.append(m)
            evidences.append(yara_evidence(has_matches=has_yara, matches=yara_matches if isinstance(yara_matches, list) else [], threat_names=threat_names, status=EvidenceStatus.OK))

        # PE static evidencia (packer/entropy/imports)
        evidences.append(pe_static_evidence(packer_indicators=packer_indicators, status=EvidenceStatus.OK))

        # Overlay evidencia (desde diet overlay_analysis)
        # Reconstruir objeto like OverlayReport si es dict
        if overlay_dict:
            # Crear evidencia overlay manualmente desde dict
            from core.evidence import Evidence, EvidenceIndicator
            ov_indicators: List[EvidenceIndicator] = []
            ov_reasons: List[str] = []
            if overlay_dict.get("overlay_present"):
                ratio = overlay_dict.get("overlay_ratio", 0.0)
                ent = overlay_dict.get("overlay_entropy", 0.0)
                ov_reasons.append(f"overlay_present ratio={ratio:.2%} entropy={ent:.2f}")
                if ratio > 0.80:
                    ov_indicators.append(EvidenceIndicator(name="overlay_ratio_high", value=ratio, weight=30))
                    ov_reasons.append(f"overlay_ratio={ratio:.1%} > 80%")
                if overlay_dict.get("embedded_pe_detected"):
                    ov_indicators.append(EvidenceIndicator(name="embedded_pe", value=overlay_dict.get("embedded_pe_count", 0), weight=25))
                    ov_reasons.append(f"embedded_pe_count={overlay_dict.get('embedded_pe_count', 0)}")
                if overlay_dict.get("overlay_yara_hits"):
                    ov_indicators.append(EvidenceIndicator(name="yara_overlay", value=overlay_dict.get("overlay_yara_hits", []), weight=35))
                    ov_reasons.append(f"yara_overlay={overlay_dict.get('overlay_yara_hits', [])}")
            has_signal = any(i.weight > 0 for i in ov_indicators)
            ov_verdict = EvidenceVerdict.SUSPICIOUS if has_signal else EvidenceVerdict.BENIGN
            ov_sev = Severity.MEDIUM if has_signal else Severity.LOW
            ov_op = OperationalStatus.SUSPICIOUS if has_signal else OperationalStatus.CLEAN
            evidences.append(Evidence(
                source=EvidenceSource.OVERLAY,
                verdict=ov_verdict,
                score=float(sum(i.weight for i in ov_indicators)),
                severity=ov_sev,
                operational_status=ov_op,
                indicators=ov_indicators,
                reasons=ov_reasons or ["no overlay signals"],
                metadata=dict(overlay_dict),
                status=EvidenceStatus.OK,
            ))
        else:
            evidences.append(overlay_evidence(overlay_report=None, status=EvidenceStatus.ERROR, error="overlay unavailable"))

        # Heuristic evidencia (desde heuristic_assessment)
        if heuristic_dict and heuristic_dict.get("risk_score") is not None:
            score_h = heuristic_dict.get("risk_score", 0)
            level = heuristic_dict.get("risk_level", "LOW")
            op_str = heuristic_dict.get("operational_status", "CLEAN")
            sev_map = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}
            op_map = {"CLEAN": OperationalStatus.CLEAN, "SUSPICIOUS": OperationalStatus.SUSPICIOUS, "DANGEROUS": OperationalStatus.DANGEROUS}
            verdict_map = {"LOW": EvidenceVerdict.BENIGN, "MEDIUM": EvidenceVerdict.SUSPICIOUS, "HIGH": EvidenceVerdict.SUSPICIOUS, "CRITICAL": EvidenceVerdict.MALICIOUS}
            evidences.append(Evidence(
                source=EvidenceSource.HEURISTIC,
                verdict=verdict_map.get(level, EvidenceVerdict.BENIGN),
                score=float(score_h),
                severity=sev_map.get(level, Severity.LOW),
                operational_status=op_map.get(op_str, OperationalStatus.CLEAN),
                indicators=[EvidenceIndicator(name=t, value=t, weight=0) for t in heuristic_dict.get("triggered_indicators", [])],
                reasons=list(heuristic_dict.get("triggered_indicators", [])) or [heuristic_dict.get("justification", "")],
                metadata=dict(heuristic_dict),
                status=EvidenceStatus.OK,
            ))
        else:
            evidences.append(heuristic_evidence(risk_assessment=None, status=EvidenceStatus.ERROR, error="heuristic unavailable"))

        # DotNet evidencia
        is_dotnet = result.get("is_dotnet", False)
        if is_dotnet and dotnet_dict:
            # Construir dotnet evidencia manualmente para preservar raw dotnet_risk
            score_d = dotnet_dict.get("dotnet_risk_score", result.get("dotnet_risk_score", 0))
            level_d = dotnet_dict.get("dotnet_risk_level", result.get("dotnet_risk_level", "LOW"))
            sev_map2 = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}
            op_map2 = {"LOW": OperationalStatus.CLEAN, "MEDIUM": OperationalStatus.CLEAN, "HIGH": OperationalStatus.SUSPICIOUS, "CRITICAL": OperationalStatus.DANGEROUS}
            verdict_map2 = {"LOW": EvidenceVerdict.BENIGN, "MEDIUM": EvidenceVerdict.SUSPICIOUS, "HIGH": EvidenceVerdict.SUSPICIOUS, "CRITICAL": EvidenceVerdict.MALICIOUS}
            reasons_d: List[str] = []
            indicators_d: List[EvidenceIndicator] = []
            if dotnet_dict.get("obfuscator_detected") or result.get("obfuscator_detected"):
                reasons_d.append(f"obfuscator={dotnet_dict.get('obfuscator_name') or result.get('obfuscator_name')}")
                indicators_d.append(EvidenceIndicator(name="obfuscator_detected", value=True, weight=20))
            if dotnet_dict.get("dotnet_risk_factors"):
                reasons_d.extend(list(dotnet_dict.get("dotnet_risk_factors", []))[:3])
            evidences.append(Evidence(
                source=EvidenceSource.DOTNET,
                verdict=verdict_map2.get(level_d, EvidenceVerdict.BENIGN),
                score=float(score_d),
                severity=sev_map2.get(level_d, Severity.LOW),
                operational_status=op_map2.get(level_d, OperationalStatus.CLEAN),
                indicators=indicators_d,
                reasons=reasons_d or [f"dotnet_risk={level_d} score={score_d}"],
                metadata=dict(dotnet_dict),
                status=EvidenceStatus.OK,
            ))
        else:
            evidences.append(dotnet_evidence(dotnet_report=None, status=EvidenceStatus.OK if not is_dotnet else EvidenceStatus.ERROR, error=None))

        # IL Behavioral evidencia
        if is_dotnet and il_dict:
            score_il = il_dict.get("dotnet_threat_score", result.get("dotnet_threat_score", 0))
            level_il = il_dict.get("dotnet_threat_level", result.get("dotnet_threat_level", "LOW"))
            sev_map3 = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}
            op_map3 = {"LOW": OperationalStatus.CLEAN, "MEDIUM": OperationalStatus.SUSPICIOUS, "HIGH": OperationalStatus.SUSPICIOUS, "CRITICAL": OperationalStatus.DANGEROUS}
            verdict_map3 = {"LOW": EvidenceVerdict.BENIGN, "MEDIUM": EvidenceVerdict.SUSPICIOUS, "HIGH": EvidenceVerdict.SUSPICIOUS, "CRITICAL": EvidenceVerdict.MALICIOUS}
            indicators_il: List[EvidenceIndicator] = []
            for k in ("injection_detected", "persistence_detected", "networking_detected", "credential_theft_detected", "worm_behavior_detected", "rat_detected", "stealer_detected"):
                if result.get(k):
                    indicators_il.append(EvidenceIndicator(name=k, value=True, weight=10))
            evidences.append(Evidence(
                source=EvidenceSource.IL_BEHAVIORAL,
                verdict=verdict_map3.get(level_il, EvidenceVerdict.BENIGN),
                score=float(score_il),
                severity=sev_map3.get(level_il, Severity.LOW),
                operational_status=op_map3.get(level_il, OperationalStatus.CLEAN),
                indicators=indicators_il,
                reasons=list(il_dict.get("family_likelihoods", {}).keys())[:3] or [f"il_threat={level_il} score={score_il}"],
                metadata=dict(il_dict),
                status=EvidenceStatus.OK,
            ))
        else:
            evidences.append(il_behavioral_evidence(il_report=None, is_dotnet=is_dotnet, status=EvidenceStatus.OK if not is_dotnet else EvidenceStatus.ERROR, error=None))

        # ── Correlacionar ─────────────────────────────────────────────
        final = self._correlation_engine.correlate(evidences)

        # ── Mapear FinalVerdict a result (sin borrar evidencias) ─────
        # Preservar score ML intacto en result["score"]; el final verdict va a campos separados
        result["evidences"] = [e.to_dict() for e in evidences]
        result["final_verdict"] = final.to_dict()
        result["correlation"] = {
            "verdict": final.verdict.value,
            "risk_level": final.risk_level.value,
            "operational_status": final.operational_status.value,
            "reasons": final.reasons,
            "contributing_sources": final.contributing_sources,
            "ml_score_preserved": final.ml_score_raw,
        }
        # Actualizar campos legacy para compatibilidad: ahora vienen del correlation, no de last writer
        # Mapear verdict a label tripartita legacy para compat con API/DTO
        verdict_to_label = {
            EvidenceVerdict.BENIGN: "BENIGN",
            EvidenceVerdict.SUSPICIOUS: "SUSPICIOUS",
            EvidenceVerdict.MALICIOUS: "MALWARE",
            EvidenceVerdict.UNKNOWN: "SUSPICIOUS",
        }
        result["label"] = verdict_to_label.get(final.verdict, result.get("label", "UNKNOWN"))
        result["operational_status"] = final.operational_status.value.upper()
        result["risk_level"] = final.risk_level.value.upper()
        # risk_score: si final es de correlacion, usar score agregado; si no, mantener heuristic score
        if final.score is not None:
            # Para compat, si final viene de ML (benign), preservar ml score; si viene de correlation, usar heuristic-like score
            # Usar heuristic score si final risk es LOW, sino usar final score
            if final.verdict == EvidenceVerdict.BENIGN:
                result["risk_score"] = int(result.get("heuristic_assessment", {}).get("risk_score", 0) or 0)
            else:
                # Final SUSPICIOUS/MALICIOUS: risk_score viene de evidencias agregadas
                result["risk_score"] = int(final.score) if final.score < 1000 else 999
        result["detection_phases"].append("CORRELATION")

        logger.info(
            "Correlacion: %s | verdict=%s risk=%s operational=%s | ml_score=%.4f preserved | sources=%s",
            file_path.name,
            final.verdict.value,
            final.risk_level.value,
            final.operational_status.value,
            final.ml_score_raw if final.ml_score_raw is not None else -1.0,
            ",".join(final.contributing_sources) or "none",
        )
        return result

    # ------------------------------------------------------------------
    # Inicialización de Módulos Auxiliares
    # ------------------------------------------------------------------

    def _resolve_pid(self, file_path: Path) -> Optional[int]:
        """Busca el PID del proceso activo que ejecuta file_path."""
        try:
            import psutil
            normalized = str(file_path.resolve()).lower()
            for proc in psutil.process_iter(["pid", "exe"]):
                try:
                    exe = proc.info.get("exe") or ""
                    if exe and str(Path(exe).resolve()).lower() == normalized:
                        return proc.info["pid"]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except Exception:
            pass
        return None

    def _run_behavioral_phase(self, file_path: Path, result: Dict[str, Any]) -> None:
        """
        Fase 7 — BehavioralShield: análisis de comportamiento dinámico.
        Timeout: BEHAVIORAL_SHIELD_TIMEOUT_SECONDS (default 2s).
        """
        from configs.settings import BEHAVIORAL_SHIELD_TIMEOUT_SECONDS
        import concurrent.futures

        result["behavioral_analysis"] = None
        if self._behavioral_shield is None or result.get("label") == "NOT_PE":
            return

        pid = self._resolve_pid(file_path)
        if pid is None:
            logger.debug("BehavioralShield: proceso no activo para %s", file_path.name)
            return

        result["detection_phases"].append("BEHAVIORAL")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._behavioral_shield.analyze_process, pid)
                report = future.result(timeout=BEHAVIORAL_SHIELD_TIMEOUT_SECONDS)

            result["behavioral_analysis"] = {
                "pid": report.pid,
                "process_name": getattr(report, "process_name", ""),
                "risk_score": report.risk_score,
                "is_suspicious": report.is_suspicious,
                "suspicious_actions": [
                    {
                        "description": getattr(a, "description", str(a)),
                        "severity": getattr(a, "severity", ""),
                        "ioc_type": getattr(a, "ioc_type", ""),
                    }
                    for a in getattr(report, "suspicious_actions", [])
                ],
                "scan_time_ms": getattr(report, "scan_time_ms", 0),
            }

            current_status = result.get("operational_status", "CLEAN")
            if report.risk_score >= 0.5 and current_status in ("CLEAN", "SUSPICIOUS"):
                result["operational_status"] = "DANGEROUS"
                logger.warning(
                    "BehavioralShield: riesgo=%.2f → DANGEROUS | pid=%d | file=%s",
                    report.risk_score, pid, file_path.name,
                )
            elif report.risk_score >= 0.3 and current_status == "CLEAN":
                result["operational_status"] = "SUSPICIOUS"
                logger.info(
                    "BehavioralShield: riesgo=%.2f → SUSPICIOUS | pid=%d | file=%s",
                    report.risk_score, pid, file_path.name,
                )

        except concurrent.futures.TimeoutError:
            logger.warning(
                "BehavioralShield timeout (%.1fs) para %s",
                BEHAVIORAL_SHIELD_TIMEOUT_SECONDS, file_path.name,
            )
        except Exception as exc:
            logger.error("Error en fase Behavioral para %s: %s", file_path.name, exc)

    def _load_model(self) -> None:
        """Carga el modelo ONNX. No lanza excepción para permitir inicio parcial."""
        try:
            self.model = ShadowNetModel(MODEL_PATH, SCALER_PATH)
            logger.info("Modelo ONNX cargado correctamente.")
        except Exception as exc:
            logger.critical(
                "El motor no pudo cargar el modelo ONNX: %s. "
                "Los escaneos ML estarán deshabilitados.",
                exc,
            )
            self.model = None

    @staticmethod
    def _init_yara():
        """Inicializa el scanner YARA. Retorna None si no está disponible."""
        try:
            from security.yara_scanner import YaraScanner
            scanner = YaraScanner()
            if scanner.is_available:
                logger.info("YARA scanner activo con %d archivo(s) de reglas.", scanner.rules_loaded)
            else:
                logger.warning(
                    "YARA scanner inactivo — no hay reglas cargadas. "
                    "Agrega archivos .yar en security/yara_rules/"
                )
            return scanner
        except Exception as exc:
            logger.warning("YARA no disponible: %s", exc)
            return None

    @staticmethod
    def _init_unpacker():
        """Inicializa el desempacador UPX. Retorna None si no está disponible."""
        try:
            from core.unpacking import UPXUnpacker
            return UPXUnpacker()
        except Exception as exc:
            logger.warning("Módulo de desempacado UPX no disponible: %s", exc)
            return None
