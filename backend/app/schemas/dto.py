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

    - pe         : Archivo PE analizado por el motor ML (features + ONNX)
    - non_pe     : Archivo no PE — no fue analizado por el modelo ML
    - realtime   : Análisis de procesos en ejecución
    - yara       : Detectado por firma YARA (sin necesidad de inferencia ML)
    """
    PE = "pe"
    NON_PE = "non_pe"
    REALTIME = "realtime"
    YARA = "yara"


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
    # ── Campos del Pipeline Híbrido ─────────────────────────────────────────
    yara_matches: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Reglas YARA que coincidieron con el archivo (vacío si ninguna)",
    )
    was_unpacked: bool = Field(
        default=False,
        description="True si el archivo fue desempacado (UPX) antes del análisis",
    )
    detection_phases: List[str] = Field(
        default_factory=list,
        description="Fases del pipeline de detección ejecutadas: YARA, UPX_DETECT, UPX_UNPACK, ML_STATIC",
    )
    # ── Telemetría .NET extendida (Mejora 8) ────────────────────────────────
    is_dotnet: bool = Field(
        default=False,
        description="True si el archivo es un ensamblado .NET/CLR",
    )
    clr_version: Optional[str] = Field(
        default=None,
        description="Versión del CLR runtime (ej: 'v4.0.30319')",
    )
    assembly_name: Optional[str] = Field(
        default=None,
        description="Nombre del ensamblado .NET",
    )
    obfuscator_detected: bool = Field(
        default=False,
        description="True si se detectó un ofuscador .NET conocido",
    )
    obfuscator_name: Optional[str] = Field(
        default=None,
        description="Nombre del ofuscador detectado (ej: 'ConfuserEx')",
    )
    embedded_assemblies_count: int = Field(
        default=0,
        description="Número de ensamblados embebidos en recursos .NET",
    )
    reflection_usage: bool = Field(
        default=False,
        description="True si se detectó uso de Reflection en el IL",
    )
    dynamic_loading_detected: bool = Field(
        default=False,
        description="True si se detectó carga dinámica de assemblies (LoadFrom/LoadFile)",
    )
    dotnet_risk_score: int = Field(
        default=0,
        description="Score de riesgo específico para .NET [0-999]",
    )
    dotnet_risk_level: str = Field(
        default="LOW",
        description="Nivel de riesgo .NET: LOW | MEDIUM | HIGH | CRITICAL",
    )
    # ── Telemetría IL Behavioral (M16) ──────────────────────────────────────
    dotnet_threat_score: int = Field(
        default=0,
        description="Score de amenaza IL 0-100 (M14)",
    )
    dotnet_threat_level: str = Field(
        default="LOW",
        description="Nivel de amenaza IL: LOW | MEDIUM | HIGH | CRITICAL",
    )
    injection_detected: bool = Field(
        default=False,
        description="True si se detectaron APIs de inyección de código",
    )
    persistence_detected: bool = Field(
        default=False,
        description="True si se detectaron mecanismos de persistencia",
    )
    networking_detected: bool = Field(
        default=False,
        description="True si se detectaron APIs de red",
    )
    credential_theft_detected: bool = Field(
        default=False,
        description="True si se detectaron indicadores de robo de credenciales",
    )
    worm_behavior_detected: bool = Field(
        default=False,
        description="True si se detectaron indicadores de propagación (worm)",
    )
    rat_detected: bool = Field(
        default=False,
        description="True si se detectaron indicadores de RAT",
    )
    stealer_detected: bool = Field(
        default=False,
        description="True si se detectaron indicadores de stealer",
    )
    top_family: Optional[str] = Field(
        default=None,
        description="Familia de malware más probable según scoring semántico",
    )
    family_likelihoods: Dict[str, Any] = Field(
        default_factory=dict,
        description="Porcentaje de similitud con cada familia conocida (M13)",
    )
    # ── SHA-256 del archivo analizado ───────────────────────────────────────
    sha256: Optional[str] = Field(
        default=None,
        description="SHA-256 del archivo calculado antes del análisis",
    )
    # ── Análisis de comportamiento dinámico (Fase 7 / BehavioralShield) ─────
    behavioral_analysis: Optional[Dict[str, Any]] = Field(
        default=None,
        description="BehaviorReport serializado o null si el proceso no estaba activo",
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
    provider: Optional[str] = Field(
        default=None,
        description=(
            "Proveedor LLM explícito (groq|gemini|ollama|template). "
            "Si se omite, el backend aplica la cascada Tri-Fallover "
            "configurada en LLM_PROVIDER / LLM_PROVIDER_ORDER."
        ),
    )
    model: Optional[str] = Field(
        default=None,
        description="Modelo específico del LLM (sobreescribe default)",
    )
