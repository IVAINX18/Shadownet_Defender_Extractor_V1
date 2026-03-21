"""
backend/app/schemas/dto.py — DTOs (Data Transfer Objects) del backend.

Defino los modelos Pydantic que validan la entrada y la salida de la API.
Sigo el formato exacto del PRD sección 19 para que el contrato con el
frontend sea consistente.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums — Uso enums para restringir valores a los definidos en el PRD
# ---------------------------------------------------------------------------

class ScanResultLabel(str, Enum):
    """Clasificación tripartita definida en el PRD."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class RiskLevel(str, Enum):
    """Nivel de riesgo operativo asociado al resultado."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanType(str, Enum):
    """Tipo de escaneo realizado."""
    SINGLE = "single"
    MULTIPLE = "multiple"
    REALTIME = "realtime"


class AnalysisType(str, Enum):
    """
    Tipo de análisis ejecutado.

    - pe: Archivo PE analizado por el motor ML (features + ONNX)
    - non_pe: Archivo no PE — no fue analizado por el modelo ML
    - realtime: Análisis de procesos en ejecución
    """
    PE = "pe"
    NON_PE = "non_pe"
    REALTIME = "realtime"


# ---------------------------------------------------------------------------
# Response DTOs — Formato de salida al frontend (PRD sección 19.1)
# ---------------------------------------------------------------------------

class ScanResult(BaseModel):
    """
    Resultado estructurado de un escaneo individual.

    Cumplo el esquema exacto del PRD sección 19.1 para que el frontend
    siempre reciba la misma estructura.
    """

    # uso use_enum_values para que Pydantic serialice los enums como
    # sus valores string planos ("benign") en vez de la representación
    # del enum ("ScanResultLabel.BENIGN"). Esto garantiza consistencia
    # en el JSON de la API y en la persistencia en Supabase.
    model_config = ConfigDict(use_enum_values=True)
    file_name: str = Field(..., description="Nombre del archivo analizado")
    scan_type: ScanType = Field(
        default=ScanType.SINGLE,
        description="Tipo de escaneo: single | multiple | realtime",
    )
    result: ScanResultLabel = Field(
        ..., description="Clasificación: benign | suspicious | malicious"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Nivel de confianza del modelo [0.0 - 1.0]"
    )
    scan_time: str = Field(
        ..., description="Tiempo de escaneo en formato legible (ej: '1.34s')"
    )
    features_detected: List[str] = Field(
        default_factory=list,
        description="Características relevantes detectadas por el extractor",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat(),
        description="Fecha y hora del escaneo en formato ISO8601",
    )
    explanation: Optional[str] = Field(
        default=None,
        description="Explicación generada por el LLM (None si modo offline)",
    )
    risk_level: RiskLevel = Field(
        ..., description="Nivel de riesgo: low | medium | high"
    )
    analysis_type: Optional[AnalysisType] = Field(
        default=None,
        description="Tipo de análisis: pe | non_pe | realtime",
    )
    user_id: Optional[str] = Field(
        default=None,
        description="ID del usuario autenticado (inyectado por el backend)",
    )
    user_email: Optional[str] = Field(
        default=None,
        description="Email del usuario autenticado (inyectado por el backend)",
    )


class ScanResponse(BaseModel):
    """
    Wrapper de respuesta exitosa de la API (PRD sección 19.6).

    Envuelvo `ScanResult` dentro de `data` para mantener un formato
    JSON estandarizado en todas las respuestas.
    """
    status: str = Field(default="success", description="Estado de la operación")
    data: ScanResult = Field(..., description="Resultado del escaneo")


class MultipleScanResponse(BaseModel):
    """Respuesta para escaneo de múltiples archivos."""
    status: str = Field(default="success", description="Estado de la operación")
    data: List[ScanResult] = Field(
        ..., description="Lista de resultados de escaneo"
    )


class ErrorResponse(BaseModel):
    """
    Respuesta de error estandarizada (PRD sección 19.7).

    Uso esta estructura para que el frontend pueda manejar errores
    de forma uniforme sin parsear formatos distintos.
    """
    status: str = Field(default="error", description="Siempre 'error'")
    message: str = Field(..., description="Descripción del error")
    code: int = Field(..., description="Código HTTP del error")


# ---------------------------------------------------------------------------
# Request DTOs — Validación de entrada
# ---------------------------------------------------------------------------

class ExplainRequest(BaseModel):
    """
    Payload para solicitar explicación LLM de un resultado de escaneo.

    Acepto un scan_result previamente generado o un file_path para
    ejecutar el escaneo primero y luego explicar.
    """
    scan_result: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Resultado de escaneo previo (preferido)",
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Ruta del archivo para escanear primero y luego explicar",
    )
    provider: str = Field(
        default="ollama",
        description="Proveedor LLM a utilizar",
    )
    model: Optional[str] = Field(
        default=None,
        description="Modelo específico del LLM (sobreescribe default)",
    )
