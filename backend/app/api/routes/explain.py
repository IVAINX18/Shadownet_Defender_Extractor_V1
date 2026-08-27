"""
backend/app/api/routes/explain.py — Endpoint GET /explain/shap (T-12).

Expone la explicabilidad SHAP del modelo ML via HTTP.
El ShapExplainer se inicializa de forma lazy (primera peticion) para
no retrasar el arranque de FastAPI cuando shap no se usa.

Seguridad:
    - Rechaza path traversal (".." en file_path).
    - Rechaza archivos que no existen.
    - Captura errores de extraccion y SHAP sin exponer stack traces.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query

from utils.logger import setup_logger

logger = setup_logger("backend.routes.explain")

router = APIRouter(prefix="/explain", tags=["explain"])

# Instancia lazy del explainer — se inicializa en la primera peticion
_explainer: Optional[Any] = None


def _get_explainer() -> Any:
    """
    Retorna el ShapExplainer compartido, inicializandolo si es necesario.

    Lanza HTTPException 503 si shap no esta instalado o los modelos no
    estan disponibles, en lugar de 500 con stack trace.
    """
    global _explainer
    if _explainer is not None:
        return _explainer
    try:
        from core.explain.shap_explainer import ShapExplainer
        _explainer = ShapExplainer()
        return _explainer
    except ImportError as exc:
        logger.error("shap no instalado: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="ShapExplainer no disponible: instalar shap>=0.44.0",
        ) from exc
    except Exception as exc:
        logger.error("Error inicializando ShapExplainer: %s", exc)
        raise HTTPException(
            status_code=503,
            detail=f"ShapExplainer no disponible: {exc}",
        ) from exc


def _validate_file_path(file_path: str) -> Path:
    """
    Valida y retorna un Path seguro para file_path.

    Rechaza:
    - Strings con ".." (path traversal).
    - Archivos que no existen.

    Args:
        file_path: Cadena de ruta recibida como query param.

    Returns:
        Path resuelto y validado.

    Raises:
        HTTPException 400 si la ruta es invalida o el archivo no existe.
    """
    if ".." in file_path:
        raise HTTPException(
            status_code=400,
            detail="file_path invalido: no se permiten componentes '..'",
        )
    p = Path(file_path)
    if not p.exists():
        raise HTTPException(
            status_code=400,
            detail=f"El archivo no existe: {file_path}",
        )
    if not p.is_file():
        raise HTTPException(
            status_code=400,
            detail=f"file_path debe ser un archivo, no un directorio",
        )
    return p


@router.get("/shap", summary="Explicacion SHAP del modelo ML para un archivo PE")
def explain_shap(
    file_path: str = Query(
        ...,
        description="Ruta absoluta o relativa al archivo PE a explicar",
    ),
    top_k: int = Query(
        20,
        ge=1,
        le=50,
        description="Numero de features a retornar (1-50)",
    ),
) -> Dict[str, Any]:
    """
    Calcula los valores SHAP para el archivo PE indicado.

    Extrae el vector de features via PEFeatureExtractor (2381 dims),
    aplica el StandardScaler de produccion y ejecuta KernelExplainer
    con un background de 100 muestras. Timeout de 30 segundos.

    Returns:
        JSON con:
        - top_features: Lista de {feature_idx, feature_name, shap_value}
        - base_value:   Expected value del explainer
        - model_score:  Score ONNX [0.0, 1.0]

    Raises:
        400: file_path invalido, archivo no existe, o no es PE valido.
        503: shap no instalado o modelos no disponibles.
    """
    p = _validate_file_path(file_path)

    # Extraer features del archivo PE
    try:
        import sys
        from pathlib import Path as _Path
        _root = _Path(__file__).resolve().parent.parent.parent.parent.parent
        if str(_root) not in sys.path:
            sys.path.insert(0, str(_root))

        from extractors.extractor import PEFeatureExtractor
        extractor = PEFeatureExtractor()
        features = extractor.extract(str(p))
    except Exception as exc:
        logger.warning("Extraccion fallida para %s: %s", p.name, exc)
        raise HTTPException(
            status_code=400,
            detail=f"Error al extraer features: {exc}",
        ) from exc

    # Calcular valores SHAP con timeout interno de 30s
    import numpy as np
    feat_array = np.asarray(features, dtype=np.float32)
    result = _get_explainer().explain(feat_array, top_k=top_k)

    # Si el explainer retorno un error controlado, exponerlo como 200 con error
    # (no es un error HTTP — es una limitacion de disponibilidad de shap)
    return result
