"""
backend/app/services/scan_service.py — Servicio de escaneo con clasificación tripartita.

Orquesto el flujo completo de escaneo:
  1. Validar archivo
  2. Ejecutar motor ML existente (ShadowNetEngine)
  3. Aplicar clasificación tripartita (benign/suspicious/malicious)
  4. Manejar archivos NO PE como suspicious (no como benign)
  5. Construir ScanResult estandarizado según PRD sección 19
"""

from __future__ import annotations

import hashlib
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

# Agrego la raíz del proyecto al path para poder importar los módulos
# existentes (core, models, extractors) sin modificarlos
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.engine import ShadowNetEngine
from utils.logger import setup_logger

from backend.app.schemas.dto import (
    AnalysisType,
    RiskLevel,
    ScanResult,
    ScanResultLabel,
    ScanType,
)

logger = setup_logger("backend.scan_service")

# ---------------------------------------------------------------------------
# Instancia compartida del motor ML — reutilizo el motor existente
# (patrón Singleton simple para evitar cargar el modelo ONNX múltiples veces)
# ---------------------------------------------------------------------------
_engine: Optional[ShadowNetEngine] = None


def get_engine() -> ShadowNetEngine:
    """
    Retorna la instancia compartida del motor ML.
    La creo en la primera llamada para evitar cargas innecesarias.
    """
    global _engine
    if _engine is None:
        logger.info("Inicializando ShadowNetEngine (primera vez)...")
        _engine = ShadowNetEngine()
    return _engine


# ---------------------------------------------------------------------------
# Clasificación tripartita — Implemento la regla del PRD
# ---------------------------------------------------------------------------

def classify_tripartite(score: float) -> Tuple[ScanResultLabel, RiskLevel]:
    """
    Aplica la clasificación tripartita basada en el score del modelo ML.

    Reglas (definidas por el usuario):
      - score < 0   → suspicious / medium  (score negativo = error de análisis)
      - score < 0.4  → benign  / low
      - 0.4 ≤ score ≤ 0.7 → suspicious / medium
      - score > 0.7  → malicious / high

    Args:
        score: Probabilidad de malware [0.0 - 1.0] del modelo ONNX.
               Un valor -1.0 indica fallo del modelo.

    Returns:
        Tupla (ScanResultLabel, RiskLevel) con la clasificación.
    """
    # 3.1 — Score negativo indica fallo de análisis → siempre SUSPICIOUS/MEDIUM
    if score < 0:
        return ScanResultLabel.SUSPICIOUS, RiskLevel.MEDIUM

    if score < 0.4:
        return ScanResultLabel.BENIGN, RiskLevel.LOW
    elif score <= 0.7:
        return ScanResultLabel.SUSPICIOUS, RiskLevel.MEDIUM
    else:
        return ScanResultLabel.MALICIOUS, RiskLevel.HIGH


# ---------------------------------------------------------------------------
# SHA-256 — Calculado en chunks para evitar OOM en archivos grandes
# ---------------------------------------------------------------------------

def _compute_sha256(file_path: Path) -> str:
    """
    Calcula el SHA-256 del archivo en chunks de 64 KB.

    Args:
        file_path: Ruta al archivo.

    Returns:
        Cadena hexadecimal del hash SHA-256.
    """
    sha256 = hashlib.sha256()
    chunk_size = 64 * 1024  # 64 KB
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


# ---------------------------------------------------------------------------
# Scan — Flujo principal de escaneo
# ---------------------------------------------------------------------------

def scan_single_file(
    file_path: Path,
    *,
    scan_type: ScanType = ScanType.SINGLE,
    enable_behavioral: bool = False,
) -> ScanResult:
    """
    Ejecuta el escaneo completo de un archivo individual.

    Flujo:
      1. Llamo a ShadowNetEngine.scan_file() (extrae features + inferencia ONNX)
      2. Si es NOT_PE → clasifico como suspicious (archivo no analizable != seguro)
      3. Si es PE válido → clasificación tripartita sobre el score ML
      4. Construyo ScanResult estandarizado

    Args:
        file_path:         Ruta absoluta al archivo a escanear.
        scan_type:         Tipo de escaneo (single, multiple, realtime).
        enable_behavioral: Si True, activa BehavioralShield (Fase 8).
                           Por defecto False para preservar comportamiento V3.

    Returns:
        ScanResult con todos los campos del PRD seccion 19.1.

    Raises:
        FileNotFoundError: Si el archivo no existe.
        RuntimeError: Si el motor ML falla.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

    engine = get_engine()
    start_time = time.time()

    # Calcula SHA-256 ANTES de ejecutar el engine
    file_sha256: Optional[str] = None
    try:
        file_sha256 = _compute_sha256(file_path)
        logger.debug("SHA-256 de %s: %s", file_path.name, file_sha256)
    except Exception as exc:
        logger.warning("No se pudo calcular SHA-256 de %s: %s", file_path.name, exc)

    # Ejecuto el motor ML existente pasando el flag behavioral
    raw_result = engine.scan_file(file_path, enable_behavioral=enable_behavioral)
    elapsed = time.time() - start_time


    # Extraer metadatos del pipeline híbrido
    yara_matches    = raw_result.get("yara_matches", [])
    was_unpacked    = raw_result.get("was_unpacked", False)
    detection_phases = raw_result.get("detection_phases", [])

    # Determino el flujo de clasificación según lo que detectó el engine
    engine_label = raw_result.get("label", "")
    is_not_pe   = engine_label == "NOT_PE"
    is_yara_hit = bool(yara_matches)  # YARA detectó una firma conocida
    is_unknown  = engine_label == "UNKNOWN"

    if is_yara_hit:
        # YARA confirmó malware por firma determinista — máxima confianza
        result_label  = ScanResultLabel.MALICIOUS
        risk_level    = RiskLevel.HIGH
        confidence    = 1.0
        analysis_type = AnalysisType.YARA

        logger.warning(
            "YARA: Malware confirmado en %s | reglas=%s | time=%.3fs",
            file_path.name,
            [m.get("rule") for m in yara_matches],
            elapsed,
        )

    elif is_not_pe:
        # Archivo NO PE — no fue analizado por el modelo ML.
        # NO lo trato como "benign" porque no puedo confirmar que sea seguro.
        # Lo clasifico como "suspicious / medium" para que el usuario investigue.
        result_label  = ScanResultLabel.SUSPICIOUS
        risk_level    = RiskLevel.MEDIUM
        confidence    = 0.0
        analysis_type = AnalysisType.NON_PE

        logger.info(
            "Archivo no PE detectado: %s | type=non_pe | result=suspicious | "
            "reason=unsupported_file_type | inference_time=%.3fs",
            file_path.name,
            elapsed,
        )

    elif is_unknown:
        # 3.2 — Engine retornó UNKNOWN (fallo de análisis en archivo PE)
        # Tratar como PE fallido: suspicious/medium con analysis_type=PE
        result_label  = ScanResultLabel.SUSPICIOUS
        risk_level    = RiskLevel.MEDIUM
        confidence    = 0.0
        analysis_type = AnalysisType.PE

        logger.warning(
            "Engine UNKNOWN para %s | análisis PE falló | result=suspicious | time=%.3fs",
            file_path.name,
            elapsed,
        )

    else:
        # Archivo PE válido — uso el score del modelo ML
        score = float(raw_result.get("score", 0.0))
        if score < 0.0:
            score = 0.0

        result_label, risk_level = classify_tripartite(score)
        confidence    = round(score, 4)
        analysis_type = AnalysisType.PE

        logger.info(
            "Archivo PE analizado: %s | type=pe | result=%s | risk=%s | "
            "score=%.4f | unpacked=%s | inference_time=%.3fs",
            file_path.name,
            result_label.value,
            risk_level.value,
            score,
            was_unpacked,
            elapsed,
        )

    # Extraigo features detectadas del resultado del motor
    details = raw_result.get("details", {})
    features: List[str] = []
    if isinstance(details, dict):
        # Combino imports y secciones sospechosas como features relevantes
        suspicious_imports  = details.get("suspicious_imports", [])
        suspicious_sections = details.get("suspicious_sections", [])
        threat_names        = details.get("threat_names", [])  # Nombres YARA
        if isinstance(suspicious_imports, list):
            features.extend([str(f) for f in suspicious_imports[:10]])
        if isinstance(suspicious_sections, list):
            features.extend([str(s) for s in suspicious_sections[:10]])
        if isinstance(threat_names, list):
            features.extend([f"YARA:{n}" for n in threat_names[:5]])

    # Construyo ScanResult estandarizado según el PRD
    scan_result = ScanResult(
        file_name=file_path.name,
        scan_type=scan_type,
        result=result_label,
        confidence=confidence,
        scan_time=f"{elapsed:.2f}s",
        features_detected=features,
        timestamp=datetime.now(timezone.utc).isoformat(),
        explanation=None,  # Se llena después si se solicita LLM
        risk_level=risk_level,
        analysis_type=analysis_type,
        # Campos del pipeline híbrido
        yara_matches=yara_matches,
        was_unpacked=was_unpacked,
        detection_phases=detection_phases,
        # Telemetría .NET extendida (Mejora 8)
        is_dotnet=raw_result.get("is_dotnet", False),
        clr_version=raw_result.get("clr_version") or None,
        assembly_name=raw_result.get("assembly_name") or None,
        obfuscator_detected=raw_result.get("obfuscator_detected", False),
        obfuscator_name=raw_result.get("obfuscator_name") or None,
        embedded_assemblies_count=raw_result.get("embedded_assemblies_count", 0),
        reflection_usage=raw_result.get("reflection_usage", False),
        dynamic_loading_detected=raw_result.get("dynamic_loading_detected", False),
        dotnet_risk_score=raw_result.get("dotnet_risk_score", 0),
        dotnet_risk_level=raw_result.get("dotnet_risk_level", "LOW"),
        # Telemetría IL Behavioral (M16)
        dotnet_threat_score=raw_result.get("dotnet_threat_score", 0),
        dotnet_threat_level=raw_result.get("dotnet_threat_level", "LOW"),
        injection_detected=raw_result.get("injection_detected", False),
        persistence_detected=raw_result.get("persistence_detected", False),
        networking_detected=raw_result.get("networking_detected", False),
        credential_theft_detected=raw_result.get("credential_theft_detected", False),
        worm_behavior_detected=raw_result.get("worm_behavior_detected", False),
        rat_detected=raw_result.get("rat_detected", False),
        stealer_detected=raw_result.get("stealer_detected", False),
        top_family=raw_result.get("top_family") or None,
        family_likelihoods=raw_result.get("family_likelihoods", {}),
        # SHA-256 calculado antes del engine
        sha256=file_sha256,
        # BehavioralShield (Fase 7)
        behavioral_analysis=raw_result.get("behavioral_analysis"),
    )

    return scan_result


def scan_multiple_files(
    file_paths: List[Path],
) -> List[ScanResult]:
    """
    Escanea múltiples archivos secuencialmente.

    Args:
        file_paths: Lista de rutas a los archivos.

    Returns:
        Lista de ScanResult, uno por archivo.
    """
    results: List[ScanResult] = []
    for fp in file_paths:
        try:
            result = scan_single_file(fp, scan_type=ScanType.MULTIPLE)
            results.append(result)
        except Exception as exc:
            # Si un archivo falla, registro el error pero continúo con los demás.
            # Lo marco como suspicious porque no puedo confirmar que sea seguro.
            logger.error("Error escaneando %s: %s", fp, exc)
            error_result = ScanResult(
                file_name=fp.name,
                scan_type=ScanType.MULTIPLE,
                result=ScanResultLabel.SUSPICIOUS,
                confidence=0.0,
                scan_time="0.00s",
                features_detected=[],
                timestamp=datetime.now(timezone.utc).isoformat(),
                explanation=f"Error durante escaneo: {exc}",
                risk_level=RiskLevel.MEDIUM,
                analysis_type=AnalysisType.NON_PE,
            )
            results.append(error_result)
    return results


# ---------------------------------------------------------------------------
# Flujo completo: Scan + Explain (opcional) + Supabase
# Conecto todo el pipeline del PRD sección 14 en una sola función.
# ---------------------------------------------------------------------------

def scan_and_explain(
    file_path: Path,
    *,
    with_explanation: bool = False,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    save_to_supabase: bool = True,
) -> ScanResult:
    """
    Flujo completo de escaneo según PRD sección 14:
    1. Escaneo ML (extractors + modelo ONNX)
    2. Clasificación tripartita
    3. Explicación LLM (opcional)
    4. Persistencia en Supabase (con fallback offline)
    5. Alerta N8N si resultado es malicious

    Args:
        file_path: Ruta al archivo a escanear.
        with_explanation: Si True, genera explicación con LLM.
        provider: Proveedor LLM (default: "ollama").
        model: Modelo LLM específico.
        save_to_supabase: Si True, guarda en Supabase.

    Returns:
        ScanResult completo con explicación si fue solicitada.
    """
    # Paso 1-2: Escaneo + clasificación tripartita
    scan_result = scan_single_file(file_path)

    # Paso 3: Explicación LLM (opcional)
    if with_explanation:
        try:
            from backend.app.services.llm_service import explain_scan_result

            llm_result = explain_scan_result(
                scan_result.model_dump(),
                provider=provider,
                model=model,
            )
            scan_result.explanation = llm_result.get("response_text", "")
            logger.info("Explicación LLM agregada al resultado de %s", file_path.name)
        except Exception as exc:
            # Si falla el LLM, retorno el resultado sin explicación
            logger.warning("LLM no disponible para %s: %s", file_path.name, exc)
            scan_result.explanation = None

    # Paso 4: Persistencia en Supabase (con fallback offline)
    if save_to_supabase:
        result_dict = scan_result.model_dump()
        try:
            from backend.app.integrations.supabase_client import save_scan_safe
            save_result = save_scan_safe(result_dict)

            if not save_result.get("saved"):
                # Supabase falló → encolar offline
                _queue_offline(result_dict)
        except Exception as exc:
            logger.warning("Error guardando en Supabase: %s — encolando offline", exc)
            _queue_offline(result_dict)

    # Paso 5: Alerta N8N delegada a send_scan_result (operational_status-aware)
    _notify_n8n(scan_result)

    return scan_result


def _queue_offline(result_dict: dict) -> None:
    """Encola un resultado para sincronización posterior."""
    try:
        from backend.app.services.offline_service import queue_scan
        queue_scan(result_dict)
    except Exception as exc:
        logger.error("Error encolando resultado offline: %s", exc)


def _notify_n8n(scan_result: ScanResult) -> None:
    """Envía alerta a N8N delegando la lógica de filtrado a send_scan_result."""
    try:
        from core.integrations.n8n_client import send_scan_result
        send_scan_result(scan_result.model_dump())
    except Exception as exc:
        logger.warning("Error enviando alerta N8N: %s", exc)


# Compatibilidad retroactiva — alias del nombre anterior
def _notify_n8n_if_malicious(scan_result: ScanResult) -> None:
    """Alias legacy — delega a _notify_n8n."""
    return _notify_n8n(scan_result)
