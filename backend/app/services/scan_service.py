"""
backend/app/services/scan_service.py — Servicio de escaneo con clasificación tripartita.

Orquesto el flujo completo de escaneo:
  1. Validar archivo
  2. Ejecutar motor ML existente (ShadowNetEngine)
  3. Aplicar clasificación tripartita (benign/suspicious/malicious)
  4. Construir ScanResult estandarizado según PRD sección 19

Mantengo la lógica de negocio separada de los endpoints para que
los routes solo se encarguen de recibir requests y devolver responses.
"""

from __future__ import annotations

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
      - score < 0.4  → benign  / low
      - 0.4 ≤ score ≤ 0.7 → suspicious / medium
      - score > 0.7  → malicious / high

    Args:
        score: Probabilidad de malware [0.0 - 1.0] del modelo ONNX.

    Returns:
        Tupla (ScanResultLabel, RiskLevel) con la clasificación.
    """
    if score < 0.4:
        return ScanResultLabel.BENIGN, RiskLevel.LOW
    elif score <= 0.7:
        return ScanResultLabel.SUSPICIOUS, RiskLevel.MEDIUM
    else:
        return ScanResultLabel.MALICIOUS, RiskLevel.HIGH


# ---------------------------------------------------------------------------
# Scan — Flujo principal de escaneo
# ---------------------------------------------------------------------------

def scan_single_file(
    file_path: Path,
    *,
    scan_type: ScanType = ScanType.SINGLE,
) -> ScanResult:
    """
    Ejecuta el escaneo completo de un archivo individual.

    Flujo:
      1. Llamo a ShadowNetEngine.scan_file() (extrae features + inferencia ONNX)
      2. Aplico clasificación tripartita sobre el score
      3. Construyo ScanResult estandarizado

    Args:
        file_path: Ruta absoluta al archivo a escanear.
        scan_type: Tipo de escaneo (single, multiple, realtime).

    Returns:
        ScanResult con todos los campos del PRD sección 19.1.

    Raises:
        FileNotFoundError: Si el archivo no existe.
        RuntimeError: Si el motor ML falla.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

    engine = get_engine()
    start_time = time.time()

    # Ejecuto el motor ML existente — no lo recreo, solo lo uso
    raw_result = engine.scan_file(file_path)
    elapsed = time.time() - start_time

    # Extraigo el score del motor
    score = float(raw_result.get("score", 0.0))
    if score < 0.0:
        score = 0.0

    # Aplico clasificación tripartita
    result_label, risk_level = classify_tripartite(score)

    # Extraigo features detectadas del resultado del motor
    details = raw_result.get("details", {})
    features: List[str] = []
    if isinstance(details, dict):
        # Combino imports y secciones sospechosas como features relevantes
        suspicious_imports = details.get("suspicious_imports", [])
        suspicious_sections = details.get("suspicious_sections", [])
        if isinstance(suspicious_imports, list):
            features.extend([str(f) for f in suspicious_imports[:10]])
        if isinstance(suspicious_sections, list):
            features.extend([str(s) for s in suspicious_sections[:10]])

    # Construyo ScanResult estandarizado según el PRD
    scan_result = ScanResult(
        file_name=file_path.name,
        scan_type=scan_type,
        result=result_label,
        confidence=round(score, 4),
        scan_time=f"{elapsed:.2f}s",
        features_detected=features,
        timestamp=datetime.now(timezone.utc).isoformat(),
        explanation=None,  # Se llena después si se solicita LLM
        risk_level=risk_level,
    )

    logger.info(
        "Escaneo completado: %s → %s (%s) en %s",
        file_path.name,
        result_label.value,
        risk_level.value,
        scan_result.scan_time,
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
            # Si un archivo falla, registro el error pero continúo con los demás
            logger.error("Error escaneando %s: %s", fp, exc)
            error_result = ScanResult(
                file_name=fp.name,
                scan_type=ScanType.MULTIPLE,
                result=ScanResultLabel.BENIGN,
                confidence=0.0,
                scan_time="0.00s",
                features_detected=[],
                timestamp=datetime.now(timezone.utc).isoformat(),
                explanation=f"Error durante escaneo: {exc}",
                risk_level=RiskLevel.LOW,
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
    4. Persistencia en Supabase (opcional)

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

    # Paso 4: Persistencia en Supabase
    if save_to_supabase:
        try:
            from backend.app.integrations.supabase_client import save_scan_safe
            save_scan_safe(scan_result.model_dump())
        except Exception as exc:
            logger.warning("Error guardando en Supabase: %s", exc)

    return scan_result
