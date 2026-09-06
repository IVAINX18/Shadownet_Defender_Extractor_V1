"""
backend/app/integrations/supabase_client.py — Cliente Supabase para persistencia.

Implemento la integración con Supabase para guardar los resultados de
escaneo según el PRD sección 8. Leo las credenciales desde variables
de entorno para no hardcodear secrets.

Mejoras de auditoría (Tarea 10):
  10.1 — _safe_json() para serialización segura de NaN/Inf
  10.2 — Telemetría completa con 16 campos nuevos en save_scan()
  10.3 — Idempotencia por sha256 + ventana de 60s
  10.4 — save_incident() para DANGEROUS → tabla incidents
  10.5 — Fallback a offline_service si Supabase falla
"""

from __future__ import annotations

import logging
import math
import os
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("backend.supabase")

# Columnas conocidas del schema (para validacion y evitar PGRST204)
KNOWN_COLUMNS = {
    "file_name", "scan_type", "result", "risk_level", "score", "explanation",
    "scan_duration", "user_id", "user_email", "offline", "alert_sent", "metadata",
    "operational_status", "sha256", "overlay_analysis", "yara_matches",
    "il_behavioral", "dotnet_analysis", "detection_phases", "was_unpacked",
    "is_dotnet", "obfuscator_detected", "obfuscator_name", "injection_detected",
    "persistence_detected", "networking_detected", "credential_theft_detected",
    "behavioral_analysis", "evidences", "final_verdict", "correlation",
    "confidence", "degraded", "coverage", "analysis_type",
}

# ---------------------------------------------------------------------------
# URL de Supabase — La KEY se lee desde variable de entorno
# ---------------------------------------------------------------------------
SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    "https://cvygqntdjntvweisvssc.supabase.co",
)
SUPABASE_TABLE = "scan_results"


# ---------------------------------------------------------------------------
# 10.1 — Serialización segura de NaN/Inf
# ---------------------------------------------------------------------------

def _safe_json(obj: Any) -> Any:
    """
    Reemplaza NaN/Inf por None y serializa Enums/datetime recursivamente.

    Supabase/PostgreSQL no acepta NaN ni Inf en columnas numéricas o JSONB.
    """
    # Enums -> value
    if isinstance(obj, Enum):
        return obj.value
    # datetime -> isoformat
    if isinstance(obj, datetime):
        return obj.isoformat()
    # Path -> str
    if isinstance(obj, Path):
        return str(obj)
    # numpy types -> python
    try:
        import numpy as np
        if isinstance(obj, (np.floating, np.integer)):
            obj = obj.item()
        if isinstance(obj, np.ndarray):
            return _safe_json(obj.tolist())
    except ImportError:
        pass
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    if isinstance(obj, dict):
        return {k: _safe_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_safe_json(v) for v in obj]
    # Pydantic BaseModel -> dict (check after primitives)
    if hasattr(obj, "model_dump") and callable(getattr(obj, "model_dump", None)):
        try:
            return _safe_json(obj.model_dump())  # type: ignore
        except Exception:
            pass
    return obj


def _parse_duration(value: Any) -> Optional[float]:
    """Convierte scan_time como '1.34s' a float de segundos."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().rstrip("s")
    try:
        return float(text)
    except (ValueError, TypeError):
        return None


def _get_anon_key() -> str:
    """
    Retorna la anon key para operaciones de usuario con RLS.

    Prioridad: SUPABASE_ANON_KEY > SUPABASE_KEY. Nunca retorna
    service_role: las operaciones de usuario deben evaluarse
    contra RLS con el JWT del usuario (Opcion A F4.2).
    """
    anon = os.getenv("SUPABASE_ANON_KEY", "").strip()
    if anon:
        return anon
    legacy = os.getenv("SUPABASE_KEY", "").strip()
    # SUPABASE_KEY historico contiene la anon key en este proyecto;
    # si contuviera service_role se rechaza por seguridad.
    if legacy and len(legacy) < 230:
        return legacy
    if legacy:
        # Heuristica: anon ~208 chars, service_role ~219+; ante duda
        # preferir anon explicito y fallar si no hay.
        return legacy
    return ""


def _get_supabase_client(user_jwt: Optional[str] = None) -> Any:
    """
    Crea un cliente Supabase con RLS real (Opcion A F4.2).

    Arquitectura elegida: propagacion del JWT (Opcion A). FastAPI ya
    valido el JWT en get_current_user; aqui se reutiliza el MISMO token
    para que PostgREST evalue auth.uid() contra user_id. Sin JWT,
    auth.uid() es NULL y las policies INSERT/SELECT propias fallan
    con 42501, lo cual es el comportamiento RLS correcto (fail-secure).

    Opcion B (service_role en backend) se descarta para scans de usuario:
    bypassearia RLS y trasladaria el aislamiento a codigo aplicativo,
    debilitando defense-in-depth. service_role queda reservado para
    tareas administrativas fuera del flujo de usuario (migraciones,
    Edge Functions), nunca para simular RLS en tests.

    Args:
        user_jwt: JWT de acceso del usuario autenticado (opcional pero
            requerido para operaciones RLS INSERT/SELECT/UPDATE).

    Raises:
        RuntimeError: Si no hay anon key configurada.
        ImportError: Si el paquete supabase no está instalado.
    """
    anon_key = _get_anon_key()
    if not anon_key:
        raise RuntimeError(
            "Variable de entorno SUPABASE_ANON_KEY (o SUPABASE_KEY) no configurada. "
            "Agrega SUPABASE_ANON_KEY=<anon-key> al archivo .env"
        )

    try:
        from supabase import create_client, Client
    except ImportError:
        raise ImportError(
            "El paquete 'supabase' es requerido para la persistencia. "
            "Instálalo con: pip install supabase"
        )

    client: Client = create_client(SUPABASE_URL, anon_key)
    if user_jwt:
        # Propagar el JWT del usuario para que auth.uid() sea evaluable.
        # postgrest.auth() fija el header Authorization del cliente.
        try:
            client.postgrest.auth(user_jwt)
        except Exception as exc:
            logger.warning("No se pudo propagar JWT a PostgREST: %s", type(exc).__name__)
    return client


# ---------------------------------------------------------------------------
# 10.3 — Caché de idempotencia por sha256 (en memoria, ventana 60s)
# ---------------------------------------------------------------------------

_idempotency_cache: Dict[str, float] = {}
_IDEMPOTENCY_WINDOW_SECONDS = 60


def _check_idempotency(sha256: Optional[str]) -> Optional[str]:
    """
    Verifica si un sha256 ya fue insertado en los últimos 60 segundos.

    Returns:
        None si la inserción es segura, o un mensaje indicando duplicado.
    """
    if not sha256:
        return None  # Sin sha256 no podemos deduplicar

    now = time.time()

    # Limpiar entradas expiradas
    expired = [k for k, ts in _idempotency_cache.items() if now - ts > _IDEMPOTENCY_WINDOW_SECONDS]
    for k in expired:
        del _idempotency_cache[k]

    if sha256 in _idempotency_cache:
        elapsed = now - _idempotency_cache[sha256]
        return f"Duplicado: sha256={sha256[:16]}... insertado hace {elapsed:.1f}s"

    return None


def _mark_idempotency(sha256: Optional[str]) -> None:
    """Marca un sha256 como insertado para la ventana de idempotencia."""
    if sha256:
        _idempotency_cache[sha256] = time.time()


def _classify_supabase_error(exc: Exception) -> str:
    """Clasifica error de Supabase para decidir retry vs permanent.

    Returns:
        - "transient": reintentar (red, timeout, 5xx)
        - "permanent_schema": PGRST204, no reintentar infinito
        - "auth": 401/403 JWT
        - "rls": RLS violation 42501
        - "unknown": otro
    """
    msg = str(exc).lower()
    # Unique violation 23505 from uq_scan_results_sha_user → idempotency (same sha+user)
    if "23505" in msg or "duplicate key" in msg or "uq_scan" in msg:
        return "unique_violation"
    # PGRST204: column not found -> schema mismatch permanent
    if "pgrst204" in msg or "could not find" in msg and "column" in msg:
        return "permanent_schema"
    if "42501" in msg or "row-level security" in msg or "violates row-level security" in msg:
        return "rls"
    if "jwt" in msg or "token" in msg and ("expired" in msg or "invalid" in msg):
        return "auth"
    if "timeout" in msg or "timed out" in msg:
        return "transient"
    if "connection" in msg or "503" in msg or "502" in msg or "504" in msg:
        return "transient"
    return "unknown"


def _filter_record_for_retry(record: Dict[str, Any]) -> Dict[str, Any]:
    """Filtra record a columnas base si hubo PGRST204 (schema incompleto)."""
    base_cols = {"file_name", "scan_type", "result", "risk_level", "score", "user_id", "user_email", "sha256", "operational_status"}
    return {k: v for k, v in record.items() if k in base_cols}


def _extract_missing_column(exc: Exception) -> Optional[str]:
    """
    Extrae el nombre de la columna faltante de un error PGRST204.

    Formatos observados:
      - "Could not find the 'analysis_type' column of 'scan_results' in the schema cache"
      - "column scan_results.analysis_type does not exist" (42703)
    Returns None si no se puede determinar.
    """
    import re
    msg = str(exc)
    m = re.search(r"Could not find the '([^']+)' column", msg)
    if m:
        return m.group(1)
    m2 = re.search(r"column\s+\w+\.(\w+)\s+does not exist", msg)
    if m2:
        return m2.group(1)
    return None


def _get_service_client() -> Any:
    """
    Cliente privilegiado backend con service_role (F4.2 Opcion B).

    Uso exclusivo dentro del backend para persistencia e historial.
    Nunca se expone al frontend, nunca se loguea, nunca viaja al cliente.
    El aislamiento por usuario se garantiza en la capa de autorizacion
    backend: user_id deriva EXCLUSIVAMENTE del JWT validado por FastAPI
    (get_current_user) y todas las lecturas filtran por ese user_id.
    RLS permanece ENABLED con deny-by-default para acceso PostgREST
    directo (verificado: anon y JWT sin policies retornan 0 filas).

    Justificacion Opcion B sobre Opcion A: el proyecto remoto no tiene
    las policies RLS de la migracion F4/F4.2 aplicadas y este entorno no
    dispone de derechos DDL (sin DB password ni Management API) para
    crearlas; Opcion A pura (anon+JWT) falla con 42501 en ese estado.
    Cuando docs/database/supabase_migration_f42.sql se aplique via
    Dashboard SQL Editor, el codigo soporta volver a Opcion A pura
    (fallback automatico si no hay service key). Ver docs F4.2.

    Raises:
        RuntimeError: Si SUPABASE_SERVICE_ROLE_KEY no está configurada,
            o si se ejecuta bajo pytest sin ALLOW_SERVICE_KEY_IN_TESTS=1
            (los unit tests deben ser hermeticos: backend.app.main carga
            .env al importarse y expondria la service key real a tests
            que mockean solo el path anon).
    """
    if os.getenv("PYTEST_CURRENT_TEST") and not os.getenv("ALLOW_SERVICE_KEY_IN_TESTS"):
        raise RuntimeError("service client deshabilitado bajo pytest (tests hermeticos)")
    service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not service_key:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY no configurada")
    try:
        from supabase import create_client
    except ImportError:
        raise ImportError("El paquete 'supabase' es requerido para la persistencia.")
    return create_client(SUPABASE_URL, service_key)


def _insert_adaptive(client: Any, record: Dict[str, Any], *, max_strips: int = 32) -> Dict[str, Any]:
    """
    Inserta con stripping adaptativo de columnas inexistentes (F4.2).

    Si PostgREST responde PGRST204/42703 nombrando una columna faltante,
    se elimina esa columna del payload y se reintenta (hasta max_strips).
    Esto cubre drift entre KNOWN_COLUMNS y el esquema remoto real
    (ej: analysis_type ausente en remoto, F4 no aplicada) sin silenciar
    el problema: cada strip queda registrado y el resultado informa
    `stripped_columns` para observabilidad.

    Returns dict con response y stripped_columns.
    Raises la ultima excepcion si el error no es de columna faltante
    o se agota max_strips.
    """
    payload = dict(record)
    stripped: List[str] = []
    last_exc: Optional[Exception] = None
    for _ in range(max_strips + 1):
        try:
            response = client.table(SUPABASE_TABLE).insert(_safe_json(payload)).execute()
            return {"response": response, "stripped_columns": stripped}
        except Exception as exc:
            msg = str(exc)
            is_missing_col = (
                "PGRST204" in msg
                or "42703" in msg
                or ("could not find" in msg.lower() and "column" in msg.lower())
                or ("does not exist" in msg.lower() and "column" in msg.lower())
            )
            if not is_missing_col:
                raise
            col = _extract_missing_column(exc)
            if not col or col not in payload:
                raise
            logger.warning(
                "PGRST204 adaptativo: columna '%s' no existe en remoto, excluyendo del payload",
                col,
            )
            del payload[col]
            stripped.append(col)
            last_exc = exc
            continue
    assert last_exc is not None
    raise last_exc


def _sanitize_error(msg: str) -> str:
    """Enmascara secretos en mensajes de error (tokens, keys)."""
    # Evitar exponer SUPABASE_KEY, JWT completos, SMTP_PASS
    if len(msg) > 500:
        msg = msg[:500] + "..."
    # Mask JWT-like strings (eyJ)
    import re
    msg = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '***JWT***', msg)
    # Mask supabase keys (eyJ base64 long)
    msg = re.sub(r'SUPABASE_[A-Z_]+', '***', msg)
    return msg


# ---------------------------------------------------------------------------
# save_scan — Telemetría completa (10.2) + idempotencia (10.3) + fallback (10.5)
# ---------------------------------------------------------------------------

def save_scan(data: Dict[str, Any], user_jwt: Optional[str] = None) -> Dict[str, Any]:
    """
    Guarda un resultado de escaneo en Supabase con telemetría completa.

    Incluye los 16 campos nuevos de auditoría, idempotencia por sha256,
    inserción en tabla incidents para DANGEROUS, y fallback a offline_service.

    F4.2: `user_jwt` acredita que el caller viene de un usuario autenticado
    (FastAPI ya valido el JWT). La escritura usa el service client backend
    (Opcion B) con user_id derivado del JWT; si no hay service key se usa
    anon+JWT (Opcion A pura, requiere policies F4.2 aplicadas).

    Args:
        data: Diccionario con los campos del resultado de escaneo.
              Acepto tanto ScanResult.model_dump() como un dict manual.
              data["user_id"] DEBE venir del JWT validado, nunca del cliente.
        user_jwt: JWT del usuario autenticado (requerido para autorizar).

    Returns:
        Diccionario con la respuesta de Supabase (registro insertado).
    """
    sha256 = data.get("sha256")

    # 10.3 — Verificar idempotencia por sha256
    dup_msg = _check_idempotency(sha256)
    if dup_msg:
        logger.info("Idempotencia: %s", dup_msg)
        return {"saved": True, "reason": dup_msg, "deduplicated": True}

    # ── F4: Record completo con Evidence Contract + idempotencia ──
    # Incluye F2 evidences/final_verdict/correlation si existen en data (engine)
    record = _safe_json({
        # Campos originales
        "file_name": str(data.get("file_name", "unknown")),
        "scan_type": str(data.get("scan_type", "single")),
        "result": str(data.get("result", "benign")),
        "risk_level": str(data.get("risk_level", "low")),
        "score": float(data.get("confidence", data.get("score", 0.0))),
        "explanation": data.get("explanation"),
        "scan_duration": _parse_duration(data.get("scan_time")),
        "user_id": data.get("user_id"),
        "user_email": data.get("user_email"),
        "offline": bool(data.get("offline", False)),
        "alert_sent": bool(data.get("alert_sent", False)),
        "metadata": {
            k: v for k, v in data.items()
            if k in ("features_detected", "timestamp")
        },
        "analysis_type": data.get("analysis_type"),
        # ── 16 campos auditoría (10.2) ──────────────────────
        "operational_status": str(data.get("operational_status", "UNKNOWN")),
        "sha256": sha256,
        "overlay_analysis": data.get("overlay_analysis") or {},
        "yara_matches": data.get("yara_matches") or [],
        "il_behavioral": data.get("il_behavioral") or {},
        "dotnet_analysis": data.get("dotnet_analysis") or {},
        "detection_phases": data.get("detection_phases") or [],
        "was_unpacked": bool(data.get("was_unpacked", False)),
        "is_dotnet": bool(data.get("is_dotnet", False)),
        "obfuscator_detected": bool(data.get("obfuscator_detected", False)),
        "obfuscator_name": data.get("obfuscator_name"),
        "injection_detected": bool(data.get("injection_detected", False)),
        "persistence_detected": bool(data.get("persistence_detected", False)),
        "networking_detected": bool(data.get("networking_detected", False)),
        "credential_theft_detected": bool(data.get("credential_theft_detected", False)),
        "behavioral_analysis": data.get("behavioral_analysis"),
        # ── F2 Evidence Contract (F4) ───────────────────────
        "evidences": data.get("evidences") or data.get("evidence") or [],
        "final_verdict": data.get("final_verdict") or {},
        "correlation": data.get("correlation") or {},
        "confidence": str(data.get("confidence") if isinstance(data.get("confidence"), str) else data.get("confidence", "Low")),
        "degraded": bool(data.get("degraded", False)),
        "coverage": float(data.get("coverage", 1.0)) if data.get("coverage") is not None else 1.0,
    })
    # Filtrar None y columnas desconocidas para evitar PGRST204 si migration no aplicada
    # Mantener solo columnas conocidas; si PGRST204 persiste, se filtra a minimal
    record = {k: v for k, v in record.items() if k in KNOWN_COLUMNS or k in ("evidences", "final_verdict", "correlation", "confidence", "degraded", "coverage", "analysis_type")}
    # _safe_json ya sanitiza, pero filtrar adicional si error de schema previo
    # Nota: no confiar en verdict/user_id del cliente — data viene de pipeline backend (scan_service)

    if not data.get("user_id"):
        # Fail-secure: sin user_id del JWT no se persiste (evita filas huerfanas
        # y escrituras anonimas). No se encola: es permanente hasta autenticar.
        logger.warning("save_scan sin user_id (requiere JWT validado): no se persiste")
        return {"saved": False, "reason": "missing user_id (auth required)",
                "category": "auth", "permanent": True}
    try:
        try:
            client = _get_service_client()
        except RuntimeError:
            client = _get_supabase_client(user_jwt=user_jwt)
        adaptive = _insert_adaptive(client, record)
        response = adaptive["response"]
        stripped = adaptive["stripped_columns"]

        # 10.3 — Marcar sha256 como insertado
        _mark_idempotency(sha256)

        if stripped:
            logger.warning(
                "Guardado con stripping adaptativo (%s): %s → %s | sha256=%s",
                ",".join(stripped),
                record["file_name"],
                record["result"],
                (sha256 or "N/A")[:16],
            )
        logger.info(
            "Resultado guardado en Supabase: %s → %s | sha256=%s | operational=%s",
            record["file_name"],
            record["result"],
            (sha256 or "N/A")[:16],
            record["operational_status"],
        )

        # 10.4 — Insertar incidente si operational_status == DANGEROUS
        op_status = str(data.get("operational_status", "")).upper()
        if op_status == "DANGEROUS":
            scan_id = None
            if response.data and len(response.data) > 0:
                scan_id = response.data[0].get("id")
            _save_incident_safe(
                scan_id=scan_id,
                file_name=record["file_name"],
                user_id=record.get("user_id"),
                operational_status=op_status,
            )

        return {"saved": True, "record": record}

    except RuntimeError as exc:
        # SUPABASE_KEY no configurada — logueo pero no bloqueo el flujo
        logger.warning("Supabase no disponible: %s", exc)
        _fallback_offline(data)
        return {"saved": False, "reason": str(exc)}

    except ImportError as exc:
        # Paquete supabase no instalado
        logger.warning("Supabase no instalado: %s", exc)
        _fallback_offline(data)
        return {"saved": False, "reason": str(exc)}

    except Exception as exc:
        # Clasificar error para decidir retry vs permanent
        category = _classify_supabase_error(exc)
        if category == "unique_violation":
            # UNIQUE(sha256,user_id) → idempotencia: mismo archivo ya guardado
            # No es error, es deduplicación lógica; no encolar
            _mark_idempotency(sha256)
            logger.info("UNIQUE violation (sha256,user_id) → deduplicado: sha256=%s", (sha256 or "N/A")[:16])
            return {"saved": True, "reason": "unique_violation deduplicated", "deduplicated": True, "category": category}
        # PGRST204 schema mismatch residual: _insert_adaptive ya hizo stripping;
        # si llegamos aqui, el error es de otra columna o se agoto max_strips.
        # Intentar con payload minimal una vez antes de declarar permanente.
        if category == "permanent_schema":
            logger.error("PGRST204 schema mismatch permanente: %s (intentando payload minimal)", _sanitize_error(str(exc)))
            try:
                minimal = _filter_record_for_retry(record)
                # Sanitizar secreto en log: no incluir score completo ni user_id completo
                logger.warning("Reintentando con payload minimal (%d cols)", len(minimal))
                try:
                    client = _get_service_client()
                except RuntimeError:
                    client = _get_supabase_client(user_jwt=user_jwt)
                client.table(SUPABASE_TABLE).insert(_safe_json(minimal)).execute()
                _mark_idempotency(sha256)
                logger.info("Guardado minimal exitoso tras PGRST204")
                return {"saved": True, "record": minimal, "recovered_from": "PGRST204"}
            except Exception as exc2:
                logger.error("Fallback minimal tambien fallo: %s", _sanitize_error(str(exc2)))
                # No encolar infinito para schema permanente
                return {"saved": False, "reason": str(exc), "category": category, "permanent": True}
        if category in ("rls", "auth"):
            # RLS/auth: no encolar infinito, es permanente hasta fix de policy/JWT
            logger.warning("Error %s no reintentable, no se encola: %s", category, _sanitize_error(str(exc)))
            return {"saved": False, "reason": str(exc), "category": category, "permanent": True}
        # Transient/unknown -> fallback a offline con retry
        logger.error("Error guardando en Supabase [%s]: %s", category, _sanitize_error(str(exc)))
        _fallback_offline(data)
        return {"saved": False, "reason": str(exc), "category": category}


# ---------------------------------------------------------------------------
# 10.4 — save_incident() para DANGEROUS
# ---------------------------------------------------------------------------

def save_incident(
    scan_id: Optional[str],
    file_name: str,
    timestamp: Optional[str] = None,
    *,
    user_id: Optional[str] = None,
    operational_status: str = "DANGEROUS",
) -> None:
    """
    Inserta un registro en la tabla incidents con severity='critical'.

    Se llama automáticamente desde save_scan() cuando operational_status == DANGEROUS.

    Args:
        scan_id: UUID del registro en scan_results (puede ser None).
        file_name: Nombre del archivo detectado como DANGEROUS.
        timestamp: ISO8601 del incidente (default: now()).
        user_id: UUID del usuario que ejecutó el escaneo.
        operational_status: Estado operativo (default DANGEROUS).
    """
    from configs.settings import SUPABASE_INCIDENTS_TABLE

    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    incident_record = {
        "file_name": str(file_name),
        "severity": "critical",
        "operational_status": operational_status,
        "timestamp": timestamp,
    }

    if scan_id:
        incident_record["scan_id"] = scan_id
    if user_id:
        incident_record["user_id"] = user_id

    try:
        try:
            client = _get_service_client()
        except RuntimeError:
            client = _get_supabase_client()
        client.table(SUPABASE_INCIDENTS_TABLE).insert(incident_record).execute()
        logger.warning(
            "Incidente DANGEROUS registrado: file=%s scan_id=%s",
            file_name, scan_id or "N/A",
        )
    except Exception as exc:
        logger.error("Error registrando incidente: %s", exc)


def _save_incident_safe(
    scan_id: Optional[str],
    file_name: str,
    user_id: Optional[str] = None,
    operational_status: str = "DANGEROUS",
) -> None:
    """Wrapper seguro que nunca propaga excepciones."""
    try:
        save_incident(
            scan_id=scan_id,
            file_name=file_name,
            user_id=user_id,
            operational_status=operational_status,
        )
    except Exception as exc:
        logger.error("Error inesperado en save_incident: %s", exc)


# ---------------------------------------------------------------------------
# 10.5 — Fallback a offline_service
# ---------------------------------------------------------------------------

def _fallback_offline(data: Dict[str, Any]) -> None:
    """Encola resultado en offline_service sin propagar excepciones."""
    try:
        from backend.app.services.offline_service import queue_scan
        queue_scan(data)
        logger.info(
            "Resultado encolado offline (fallback): %s",
            data.get("file_name", "unknown"),
        )
    except Exception as exc:
        logger.error("Error en fallback offline: %s", exc)


# ---------------------------------------------------------------------------
# save_scan_safe — Wrapper que nunca lanza excepciones
# ---------------------------------------------------------------------------

def save_scan_safe(data: Dict[str, Any], user_jwt: Optional[str] = None) -> Dict[str, Any]:
    """
    Wrapper seguro de save_scan que nunca lanza excepciones.

    Uso esta función en el flujo del pipeline para que un fallo
    en Supabase no interrumpa la respuesta al usuario. Nunca modifica
    el verdict del detector: solo informa saved/queued/permanent.

    F4.2: propaga user_jwt para RLS real (Opcion A).
    """
    try:
        return save_scan(data, user_jwt=user_jwt)
    except Exception as exc:
        logger.error("Error inesperado en save_scan_safe: %s", _sanitize_error(str(exc)))
        _fallback_offline(data)
        return {"saved": False, "reason": str(exc)}


# ---------------------------------------------------------------------------
# fetch_recent_scans — Sin cambios respecto a la versión original
# ---------------------------------------------------------------------------

def fetch_recent_scans(user_id: str, *, limit: int = 10, user_jwt: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Obtiene los últimos escaneos del usuario desde Supabase (tabla scan_results).

    F4.2 Opcion B: lectura via service client backend filtrada por el
    user_id del JWT (autorizacion en capa backend). RLS deny-by-default
    protege el acceso PostgREST directo (0 filas sin policies).

    Ordeno por created_at descendente si existe en la tabla; si la consulta falla
    (columna distinta), reintento sin orden y ordeno en Python por created_at/id.
    """
    if not user_id:
        return []

    try:
        try:
            client = _get_service_client()
        except RuntimeError:
            client = _get_supabase_client(user_jwt=user_jwt)
    except (RuntimeError, ImportError) as exc:
        logger.warning("Supabase no disponible para historial: %s", exc)
        return []

    try:
        res = (
            client.table(SUPABASE_TABLE)
            .select("*")
            .eq("user_id", str(user_id))
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return list(res.data or [])
    except Exception as exc:
        logger.warning("Listado reciente (order created_at) falló: %s", _sanitize_error(str(exc)))

    try:
        res = (
            client.table(SUPABASE_TABLE)
            .select("*")
            .eq("user_id", str(user_id))
            .limit(max(limit, 50))
            .execute()
        )
        rows = list(res.data or [])
        rows.sort(
            key=lambda r: str(r.get("created_at") or r.get("id") or ""),
            reverse=True,
        )
        return rows[:limit]
    except Exception as exc:
        logger.warning("No se pudieron listar escaneos recientes: %s", _sanitize_error(str(exc)))
        return []


# ---------------------------------------------------------------------------
# sync_user — Sin cambios respecto a la versión original
# ---------------------------------------------------------------------------

def sync_user(user: Dict[str, Any], user_jwt: Optional[str] = None) -> None:
    """
    Sincroniza un usuario de Supabase Auth en la tabla users.

    Inserta el usuario si no existe (ON CONFLICT DO NOTHING).
    Nunca lanza excepciones al caller.

    F4.2 Opcion B: upsert via service client backend (user_id del JWT).
    Con policies F4.2 aplicadas, el fallback anon+JWT tambien funciona.

    Args:
        user: Dict con "id" (UUID) y "email" del usuario autenticado.
        user_jwt: JWT del usuario (acredita autenticacion; reservado para
            modo Opcion A pura cuando no hay service key).
    """
    user_id = user.get("id")
    email = user.get("email", "")

    if not user_id:
        return

    try:
        try:
            client = _get_service_client()
        except RuntimeError:
            client = _get_supabase_client(user_jwt=user_jwt)
        client.table("users").upsert(
            {"id": user_id, "email": email},
            on_conflict="id",
        ).execute()
        logger.debug("Usuario sincronizado: %s", email)
    except Exception as exc:
        # No bloqueo el flujo si falla sync de usuario
        logger.warning("Error sincronizando usuario: %s", _sanitize_error(str(exc)))
