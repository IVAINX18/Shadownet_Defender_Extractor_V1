"""
core/heuristics/__init__.py — Motor heurístico de riesgo independiente del modelo ML.

Este módulo opera en paralelo al modelo ONNX sin modificar su salida.
Genera una clasificación de riesgo basada en indicadores estructurales
y forenses que el modelo de ML no puede capturar directamente.

Justificación del diseño:
    El modelo SOREL-20M fue entrenado sobre features del PE principal.
    Técnicas como overlays cifrados, PEs embebidos o droppers con stub
    benigno pueden evadir el modelo porque las features del stub parecen
    legítimas. El motor heurístico cierra esa brecha sin reentrenar.

Compatibilidad:
    - No modifica el vector de 2381 features.
    - No modifica la inferencia ONNX.
    - No modifica el scaler.
    - Genera un resultado paralelo: risk_score / risk_level / operational_status.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from utils.logger import setup_logger

logger = setup_logger(__name__)


@dataclass
class RiskAssessment:
    """Resultado del análisis heurístico de riesgo."""
    risk_score: int
    risk_level: str           # LOW / MEDIUM / HIGH / CRITICAL
    operational_status: str   # CLEAN / SUSPICIOUS / DANGEROUS
    triggered_indicators: List[str]
    justification: str

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "operational_status": self.operational_status,
            "triggered_indicators": self.triggered_indicators,
            "justification": self.justification,
        }


class HeuristicRiskEngine:
    """
    Motor heurístico de riesgo independiente del modelo ML.

    Genera una puntuación de riesgo (0-100+) a partir de indicadores
    estructurales y forenses, y la convierte en una clasificación
    operativa paralela al resultado del modelo ONNX.

    Justificación de pesos:

    overlay_ratio_high (30 pts):
        Un overlay > 80% del archivo es extremadamente inusual en
        software legítimo. Los instaladores usan las secciones PE,
        no raw overlays. Es el indicador primario de dropper.

    overlay_entropy_high (25 pts):
        Entropía > 7.2 bits en el overlay indica cifrado o compresión.
        Combinado con overlay grande, es la firma clásica de un dropper.

    embedded_pe (25 pts):
        Encontrar una estructura PE válida dentro del overlay es
        evidencia directa de arquitectura dropper/loader.

    yara_overlay / yara_embedded (35 pts c/u):
        La confirmación por firma es la señal más confiable.
        Tiene el mayor peso porque es determinista.

    rwx_sections (15 pts):
        Secciones RWX = código automodificable o shellcode.

    very_low_imports (15 pts):
        Los stubs de packers minimizan su IAT para evitar análisis.
        < 10 imports + otros indicadores = muy sospechoso.

    Descuento por instaladores conocidos (-20 pts):
        NSIS, InnoSetup, InstallShield, SFX archivos: tienen overlays
        grandes legítimamente. Se penaliza el score para evitar FPs.
    """

    WEIGHTS: Dict[str, int] = {
        "overlay_ratio_high":       30,   # overlay > 80%
        "overlay_ratio_very_high":  15,   # overlay > 93% (acumulativo)
        "overlay_entropy_high":     25,   # entropy > 7.2
        "overlay_entropy_critical": 10,   # entropy > 7.8 (acumulativo)
        "embedded_pe":              25,   # PE válido en overlay
        "yara_overlay":             35,   # YARA hit en overlay
        "yara_embedded":            35,   # YARA hit en PE embebido
        "rwx_sections":             15,   # Secciones RWX presentes
        "packer_detected":          10,   # Indicadores generales de packer
        "very_low_imports":         15,   # < 10 imports
        "no_imports":               20,   # 0 imports
        "high_global_entropy":      15,   # entropía global > 7.5
        "overlay_has_suspicious_strings": 10,  # Strings de inyección en overlay
        "ml_score_uncertain":        5,   # Score ML en rango incierto [0.3, 0.7]
    }

    # Umbrales de nivel de riesgo
    THRESHOLDS: Dict[str, tuple] = {
        "LOW":      (0,  20),
        "MEDIUM":   (21, 50),
        "HIGH":     (51, 79),
        "CRITICAL": (80, 9999),
    }

    # Descuento por instalador legítimo conocido
    INSTALLER_DISCOUNT = -20

    def assess(
        self,
        overlay_report,
        packer_indicators: Optional[dict] = None,
        ml_score: Optional[float] = None,
    ) -> RiskAssessment:
        """
        Calcula el riesgo heurístico combinando todos los indicadores.

        Args:
            overlay_report: OverlayReport generado por OverlayAnalyzer.
            packer_indicators: Dict de detect_packer_features() del extractor.
            ml_score: Score del modelo ONNX (para contexto, no modifica la lógica).

        Returns:
            RiskAssessment con score, nivel y clasificación operativa.
        """
        score = 0
        triggered: List[str] = []
        packer = packer_indicators or {}

        # ── Indicadores de overlay ─────────────────────────────────────
        if overlay_report.overlay_present:
            ratio = overlay_report.overlay_ratio
            ent = overlay_report.overlay_entropy

            if ratio > 0.80:
                score += self.WEIGHTS["overlay_ratio_high"]
                triggered.append(f"overlay_ratio={ratio:.1%} > 80%")

            if ratio > 0.93:
                score += self.WEIGHTS["overlay_ratio_very_high"]
                triggered.append(f"overlay_ratio={ratio:.1%} > 93% (crítico)")

            if ent > 7.2:
                score += self.WEIGHTS["overlay_entropy_high"]
                triggered.append(f"overlay_entropy={ent:.4f} > 7.2 (cifrado/comprimido)")

            if ent > 7.8:
                score += self.WEIGHTS["overlay_entropy_critical"]
                triggered.append(f"overlay_entropy={ent:.4f} > 7.8 (máxima aleatoriedad)")

            if overlay_report.embedded_pe_detected:
                score += self.WEIGHTS["embedded_pe"]
                triggered.append(
                    f"embedded_pe_count={overlay_report.embedded_pe_count} "
                    f"@ offsets={overlay_report.embedded_pe_offsets[:3]}"
                )

            if overlay_report.overlay_yara_hits:
                score += self.WEIGHTS["yara_overlay"]
                triggered.append(f"yara_overlay_hits={overlay_report.overlay_yara_hits}")

            if overlay_report.embedded_pe_yara_hits:
                score += self.WEIGHTS["yara_embedded"]
                triggered.append(f"yara_embedded_hits={overlay_report.embedded_pe_yara_hits}")

            if overlay_report.overlay_suspicious_strings:
                score += self.WEIGHTS["overlay_has_suspicious_strings"]
                triggered.append(
                    f"overlay_suspicious_strings={len(overlay_report.overlay_suspicious_strings)}"
                )

        # ── Entropía global ────────────────────────────────────────────
        if overlay_report.global_entropy > 7.5:
            score += self.WEIGHTS["high_global_entropy"]
            triggered.append(f"global_entropy={overlay_report.global_entropy:.4f} > 7.5")

        # ── Indicadores de estructura PE ───────────────────────────────
        if packer.get("rwx_sections", 0) > 0:
            score += self.WEIGHTS["rwx_sections"]
            triggered.append(f"rwx_sections={packer['rwx_sections']}")

        if packer.get("packer_detected"):
            score += self.WEIGHTS["packer_detected"]
            triggered.append("packer_indicators=True")

        num_imports = packer.get("num_imports", -1)
        if num_imports == 0:
            score += self.WEIGHTS["no_imports"]
            triggered.append("no_imports (posible dropper sin IAT)")
        elif 0 < num_imports < 10:
            score += self.WEIGHTS["very_low_imports"]
            triggered.append(f"very_low_imports={num_imports}")

        # ── Incertidumbre del modelo ML ────────────────────────────────
        if ml_score is not None and 0.30 <= ml_score <= 0.70:
            score += self.WEIGHTS["ml_score_uncertain"]
            triggered.append(f"ml_score={ml_score:.4f} en rango incierto [0.3, 0.7]")

        # ── Protección contra falsos positivos ─────────────────────────
        if overlay_report.is_known_installer:
            score = max(0, score + self.INSTALLER_DISCOUNT)
            triggered.append(
                f"FP_protection: instalador_conocido={overlay_report.installer_type} "
                f"(-{abs(self.INSTALLER_DISCOUNT)} pts)"
            )

        risk_level = self._classify_level(score)
        operational_status = self._operational_status(risk_level, ml_score)
        justification = self._build_justification(risk_level, score, triggered)

        logger.info(
            "Heurística — score=%d level=%s operational=%s | triggers=%d",
            score, risk_level, operational_status, len(triggered),
        )

        return RiskAssessment(
            risk_score=min(score, 999),
            risk_level=risk_level,
            operational_status=operational_status,
            triggered_indicators=triggered,
            justification=justification,
        )

    # ------------------------------------------------------------------
    # Clasificación
    # ------------------------------------------------------------------

    def _classify_level(self, score: int) -> str:
        for level, (low, high) in self.THRESHOLDS.items():
            if low <= score <= high:
                return level
        return "CRITICAL"

    def _operational_status(self, risk_level: str, ml_score: Optional[float]) -> str:
        """
        Clasifica el estado operativo combinando ML + heurística.

        Matriz de decisión:
            ML MALWARE  +  cualquier heurística  → DANGEROUS
            ML BENIGN   +  LOW                   → CLEAN
            ML BENIGN   +  MEDIUM / HIGH          → SUSPICIOUS
            ML BENIGN   +  CRITICAL               → DANGEROUS
        """
        if ml_score is not None and ml_score >= 0.5:
            return "DANGEROUS"

        mapping = {
            "LOW":      "CLEAN",
            "MEDIUM":   "SUSPICIOUS",
            "HIGH":     "SUSPICIOUS",
            "CRITICAL": "DANGEROUS",
        }
        return mapping.get(risk_level, "SUSPICIOUS")

    def _build_justification(self, risk_level: str, score: int, triggered: list) -> str:
        if not triggered:
            return f"Risk {risk_level} (score={score}). No heuristic indicators triggered."
        summary = f"Risk {risk_level} (score={score}). Triggered {len(triggered)} indicator(s): "
        return summary + " | ".join(triggered[:6])
