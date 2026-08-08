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

Mejora 2 — Context-Aware Risk Engine:
    Los ensamblados .NET tienen características que en PE nativos serían
    señales de alerta pero que en .NET son completamente normales:
        - Muy pocos imports (dependen de mscoree.dll, no de Win32 directo)
        - Entropía elevada (metadatos IL comprimidos, recursos GZIP)
        - Recursos grandes (imágenes WPF, localizaciones, assemblies satélite)
    Cuando is_dotnet=True, se aplica una matriz de pesos diferenciada
    que reduce el score de indicadores con alta tasa de FP en .NET.

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

    Mejora 2 — Context-Aware Risk Engine:
    ─────────────────────────────────────
    Cuando is_dotnet=True se aplican pesos reducidos para indicadores
    que tienen alta tasa de falso positivo en ensamblados .NET legítimos:

    very_low_imports / no_imports → reducidos a 0 en .NET
        Justificación: Todo ensamblado .NET carga código vía CLR/JIT.
        La IAT nativa solo contiene mscoree.dll::_CorExeMain o similar.
        Un Assembly WinForms legítimo tendrá 1-3 imports nativos.
        Este indicador es inútil como señal de peligro en .NET.

    high_global_entropy → reducido 60% en .NET
        Justificación: Los metadatos IL, las tablas de strings y los
        recursos comprimidos GZIP elevan la entropía de forma normal.
        Entropía de 7.5+ es esperable en assemblies con recursos ricos.
        Solo se mantiene como indicador leve de soporte.

    packer_detected → reducido 50% en .NET
        Justificación: Herramientas como ConfuserEx o SmartAssembly
        producen las mismas firmas que detectaríamos como "packer" en
        PE nativo. Sin evidencia adicional, no es determinante.

    Indicadores que MANTIENEN su peso en .NET (igual o mayor):
        overlay_ratio_high / overlay_entropy_high:
            Un .NET legítimo rarísimamente tiene overlay. Si lo tiene
            con alta entropía, sigue siendo altamente sospechoso.

        embedded_pe:
            Un PE dentro del overlay de un .NET assembly es siempre
            sospechoso — no hay justificación legítima para esto.

        yara_overlay / yara_embedded:
            Las firmas YARA son deterministas. No cambian con contexto.

        rwx_sections:
            Secciones RWX siguen siendo anómalas en cualquier PE,
            incluyendo .NET (el JIT usa memoria propias del CLR, no
            secciones RWX en el PE en disco).

    Tabla resumen de pesos diferenciados:

        Indicador                  | PE Nativo | .NET Assembly
        ─────────────────────────────────────────────────────
        overlay_ratio_high         |    30     |    30  (igual)
        overlay_ratio_very_high    |    15     |    15  (igual)
        overlay_entropy_high       |    25     |    25  (igual)
        overlay_entropy_critical   |    10     |    10  (igual)
        embedded_pe                |    25     |    25  (igual)
        yara_overlay               |    35     |    35  (igual)
        yara_embedded              |    35     |    35  (igual)
        rwx_sections               |    15     |    15  (igual)
        packer_detected            |    10     |     5  (-50%)
        very_low_imports           |    15     |     0  (FP .NET)
        no_imports                 |    20     |     0  (FP .NET)
        high_global_entropy        |    15     |     6  (-60%)
        overlay_suspicious_strings |    10     |    10  (igual)
        ml_score_uncertain         |     5     |     5  (igual)
    """

    # Pesos base — PE nativo (comportamiento original, sin cambios)
    WEIGHTS: Dict[str, int] = {
        "overlay_ratio_high":       30,
        "overlay_ratio_very_high":  15,
        "overlay_entropy_high":     25,
        "overlay_entropy_critical": 10,
        "embedded_pe":              25,
        "yara_overlay":             35,
        "yara_embedded":            35,
        "rwx_sections":             15,
        "packer_detected":          10,
        "very_low_imports":         15,
        "no_imports":               20,
        "high_global_entropy":      15,
        "overlay_has_suspicious_strings": 10,
        "ml_score_uncertain":        5,
    }

    # Pesos diferenciados para ensamblados .NET (Mejora 2)
    # Solo se listan los que DIFIEREN del valor base.
    WEIGHTS_DOTNET_OVERRIDE: Dict[str, int] = {
        "packer_detected":    5,   # ConfuserEx/Dotfuscator → reducido 50%
        "very_low_imports":   0,   # IAT minimal es NORMAL en .NET → sin puntos
        "no_imports":         0,   # Ídem — mscoree.dll no cuenta como "sin imports"
        "high_global_entropy": 6,  # IL comprimido eleva entropía normalmente → reducido 60%
    }

    # Descuento adicional cuando is_dotnet=True y sin indicadores graves
    # (protección genérica contra FP en .NET legítimo)
    DOTNET_BASELINE_DISCOUNT = -10

    # Umbrales de nivel de riesgo (sin cambios)
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
        dotnet_report=None,
    ) -> RiskAssessment:
        """
        Calcula el riesgo heurístico combinando todos los indicadores.

        Args:
            overlay_report:   OverlayReport generado por OverlayAnalyzer.
            packer_indicators: Dict de detect_packer_features() del extractor.
            ml_score:         Score del modelo ONNX (contexto, no modifica lógica).
            dotnet_report:    DotNetReport opcional — activa la matriz de pesos .NET
                              cuando is_dotnet=True (Mejora 2).

        Returns:
            RiskAssessment con score, nivel y clasificación operativa.
        """
        # ── Determinar si aplicar pesos .NET (Mejora 2) ────────────────
        is_dotnet = False
        if dotnet_report is not None and getattr(dotnet_report, "is_dotnet", False):
            is_dotnet = True

        def w(key: str) -> int:
            """Retorna el peso correcto según contexto PE nativo / .NET."""
            if is_dotnet and key in self.WEIGHTS_DOTNET_OVERRIDE:
                return self.WEIGHTS_DOTNET_OVERRIDE[key]
            return self.WEIGHTS[key]

        score = 0
        triggered: List[str] = []
        packer = packer_indicators or {}

        if is_dotnet:
            triggered.append("context=dotnet_assembly (pesos ajustados para .NET)")

        # ── Indicadores de overlay ─────────────────────────────────────
        if overlay_report.overlay_present:
            ratio = overlay_report.overlay_ratio
            ent = overlay_report.overlay_entropy

            if ratio > 0.80:
                score += w("overlay_ratio_high")
                triggered.append(f"overlay_ratio={ratio:.1%} > 80%")

            if ratio > 0.93:
                score += w("overlay_ratio_very_high")
                triggered.append(f"overlay_ratio={ratio:.1%} > 93% (crítico)")

            if ent > 7.2:
                score += w("overlay_entropy_high")
                triggered.append(f"overlay_entropy={ent:.4f} > 7.2 (cifrado/comprimido)")

            if ent > 7.8:
                score += w("overlay_entropy_critical")
                triggered.append(f"overlay_entropy={ent:.4f} > 7.8 (máxima aleatoriedad)")

            if overlay_report.embedded_pe_detected:
                score += w("embedded_pe")
                triggered.append(
                    f"embedded_pe_count={overlay_report.embedded_pe_count} "
                    f"@ offsets={overlay_report.embedded_pe_offsets[:3]}"
                )

            if overlay_report.overlay_yara_hits:
                score += w("yara_overlay")
                triggered.append(f"yara_overlay_hits={overlay_report.overlay_yara_hits}")

            if overlay_report.embedded_pe_yara_hits:
                score += w("yara_embedded")
                triggered.append(f"yara_embedded_hits={overlay_report.embedded_pe_yara_hits}")

            if overlay_report.overlay_suspicious_strings:
                score += w("overlay_has_suspicious_strings")
                triggered.append(
                    f"overlay_suspicious_strings={len(overlay_report.overlay_suspicious_strings)}"
                )

        # ── Entropía global ────────────────────────────────────────────
        if overlay_report.global_entropy > 7.5:
            score += w("high_global_entropy")
            triggered.append(
                f"global_entropy={overlay_report.global_entropy:.4f} > 7.5"
                + (" (peso reducido en .NET)" if is_dotnet else "")
            )

        # ── Indicadores de estructura PE ───────────────────────────────
        if packer.get("rwx_sections", 0) > 0:
            score += w("rwx_sections")
            triggered.append(f"rwx_sections={packer['rwx_sections']}")

        if packer.get("packer_detected"):
            score += w("packer_detected")
            triggered.append(
                "packer_indicators=True"
                + (" (podría ser ofuscador .NET, peso reducido)" if is_dotnet else "")
            )

        num_imports = packer.get("num_imports", -1)
        if num_imports == 0:
            pts = w("no_imports")
            if pts > 0:
                score += pts
                triggered.append("no_imports (posible dropper sin IAT)")
            elif is_dotnet:
                triggered.append(
                    "no_imports=0 — normal en .NET (mscoree.dll implícita, sin penalización)"
                )
        elif 0 < num_imports < 10:
            pts = w("very_low_imports")
            if pts > 0:
                score += pts
                triggered.append(f"very_low_imports={num_imports}")
            elif is_dotnet:
                triggered.append(
                    f"imports={num_imports} — normal en .NET (solo mscoree/ntdll, sin penalización)"
                )

        # ── Incertidumbre del modelo ML ────────────────────────────────
        if ml_score is not None and 0.30 <= ml_score <= 0.70:
            score += w("ml_score_uncertain")
            triggered.append(f"ml_score={ml_score:.4f} en rango incierto [0.3, 0.7]")

        # ── Protección genérica .NET contra FP ────────────────────────
        # Si es .NET y no hay indicadores graves (overlay/embedded/YARA),
        # aplicamos un descuento base para compensar la mayor ruido de .NET.
        if is_dotnet:
            has_grave_indicators = any(
                kw in " ".join(triggered)
                for kw in ["overlay_ratio", "embedded_pe", "yara_", "rwx_sections"]
            )
            if not has_grave_indicators:
                score = max(0, score + self.DOTNET_BASELINE_DISCOUNT)
                triggered.append(
                    f"FP_protection: .NET sin indicadores graves "
                    f"({self.DOTNET_BASELINE_DISCOUNT} pts)"
                )

        # ── Protección contra falsos positivos por instalador ──────────
        if overlay_report.is_known_installer:
            score = max(0, score + self.INSTALLER_DISCOUNT)
            triggered.append(
                f"FP_protection: instalador_conocido={overlay_report.installer_type} "
                f"(-{abs(self.INSTALLER_DISCOUNT)} pts)"
            )

        risk_level = self._classify_level(score)
        operational_status = self._operational_status(risk_level, ml_score, is_dotnet)
        justification = self._build_justification(risk_level, score, triggered)

        logger.info(
            "Heurística — score=%d level=%s operational=%s is_dotnet=%s | triggers=%d",
            score, risk_level, operational_status, is_dotnet, len(triggered),
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

    def _operational_status(
        self, risk_level: str, ml_score: Optional[float], is_dotnet: bool = False
    ) -> str:
        """
        Clasifica el estado operativo combinando ML + heurística.

        Matriz de decisión (PE nativo):
            ML MALWARE  +  cualquier heurística  → DANGEROUS
            ML BENIGN   +  LOW                   → CLEAN
            ML BENIGN   +  MEDIUM / HIGH          → SUSPICIOUS
            ML BENIGN   +  CRITICAL               → DANGEROUS

        Ajuste .NET (Mejora 2):
            ML BENIGN   +  MEDIUM (solo entropy/packer, sin overlay/PE)
                        → CLEAN en contexto .NET (estos son FP esperados)
            ML BENIGN   +  HIGH sin embedded PE   → SUSPICIOUS (no DANGEROUS)
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
