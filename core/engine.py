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

    # ------------------------------------------------------------------
    # API Pública
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Escanea un archivo usando el pipeline híbrido completo.

        Returns:
            Diccionario con:
                - label     : "MALWARE" | "BENIGN" | "NOT_PE"
                - score     : Float [0.0, 1.0]
                - status    : "detected" | "clean" | "not_supported"
                - confidence: "High" | "Medium" | "Low"
                - details   : Diccionario con información adicional
                - yara_matches : Lista de reglas YARA que coincidieron
                - was_unpacked : Bool — si el archivo fue desempacado
        """
        file_path = Path(file_path)
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
            "operational_status": "UNKNOWN",   # CLEAN / SUSPICIOUS / DANGEROUS
            "risk_level": "LOW",
            "risk_score": 0,
            "overlay_analysis": {},
            "heuristic_assessment": {},
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
        self._run_overlay_phase(file_path, result)

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

            if yara_scan.has_matches:
                threat_names = yara_scan.threat_names
                categories = yara_scan.categories

                logger.warning(
                    "YARA: Amenaza confirmada en %s — Reglas: %s | Categorías: %s",
                    file_path.name,
                    threat_names,
                    categories,
                )

                # Construir resultado de MALWARE con score máximo
                yara_result = dict(result)
                yara_result.update({
                    "status": "detected",
                    "label": "MALWARE",
                    "score": 1.0,
                    "confidence": "High",
                    "detection_phases": ["YARA"],
                    "yara_matches": [
                        {
                            "rule": m.rule_name,
                            "category": m.category,
                            "tags": m.tags,
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

            features = self.extractor.extract(str(analysis_path))
            
            # Integrar diagnósticos de auditoría y packing en los detalles del resultado (Mejora 6)
            if hasattr(self.extractor, "last_diagnostics") and self.extractor.last_diagnostics:
                result["details"].update(self.extractor.last_diagnostics)

            if self.model:
                score = self.model.predict(features)
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

        except Exception as exc:
            logger.error("Fallo en fase ML para %s: %s", analysis_path, exc)
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

    # ------------------------------------------------------------------
    # Inicialización de Módulos Auxiliares
    # ------------------------------------------------------------------

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
