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
from typing import Any, Dict, List, Optional

logger = logging.getLogger("backend.supabase")

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
    Reemplaza NaN/Inf por None recursivamente para serialización segura.

    Supabase/PostgreSQL no acepta NaN ni Inf en columnas numéricas o JSONB.
    Esta función los convierte a None antes de la inserción.
    """
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    if isinstance(obj, dict):
        return {k: _safe_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_safe_json(v) for v in obj]
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


def _get_supabase_client() -> Any:
    """
    Crea y retorna un cliente de Supabase.

    Leo SUPABASE_KEY desde variables de entorno para no hardcodear
    credenciales en el código fuente.

    Raises:
        RuntimeError: Si la variable SUPABASE_KEY no está configurada.
        ImportError: Si el paquete supabase no está instalado.
    """
    supabase_key = os.getenv("SUPABASE_KEY", "").strip()
    if not supabase_key:
        raise RuntimeError(
            "Variable de entorno SUPABASE_KEY no configurada. "
            "Agrega SUPABASE_KEY=<tu-api-key> al archivo .env"
        )

    try:
        from supabase import create_client, Client
    except ImportError:
        raise ImportError(
            "El paquete 'supabase' es requerido para la persistencia. "
            "Instálalo con: pip install supabase"
        )

    client: Client = create_client(SUPABASE_URL, supabase_key)
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


# ---------------------------------------------------------------------------
# save_scan — Telemetría completa (10.2) + idempotencia (10.3) + fallback (10.5)
# ---------------------------------------------------------------------------

def save_scan(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Guarda un resultado de escaneo en Supabase con telemetría completa.

    Incluye los 16 campos nuevos de auditoría, idempotencia por sha256,
    inserción en tabla incidents para DANGEROUS, y fallback a offline_service.

    Args:
        data: Diccionario con los campos del resultado de escaneo.
              Acepto tanto ScanResult.model_dump() como un dict manual.

    Returns:
        Diccionario con la respuesta de Supabase (registro insertado).
    """
    sha256 = data.get("sha256")

    # 10.3 — Verificar idempotencia por sha256
    dup_msg = _check_idempotency(sha256)
    if dup_msg:
        logger.info("Idempotencia: %s", dup_msg)
        return {"saved": True, "reason": dup_msg, "deduplicated": True}

    # 10.2 — Record completo con todos los campos de telemetría
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
        # Fase 1 n8n→Resend: idempotencia para Edge Function (evita duplicados en retries)
        "alert_sent": bool(data.get("alert_sent", False)),
        "metadata": {
            k: v for k, v in data.items()
            if k in ("features_detected", "timestamp")
        },
        # ── 16 campos nuevos de auditoría (10.2) ──────────────────────
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
    })

    try:
        client = _get_supabase_client()
        response = (
            client.table(SUPABASE_TABLE)
            .insert(record)
            .execute()
        )

        # 10.3 — Marcar sha256 como insertado
        _mark_idempotency(sha256)

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
        # Error de red, permisos, etc. — fallback a offline
        logger.error("Error guardando en Supabase: %s", exc)
        _fallback_offline(data)
        return {"saved": False, "reason": str(exc)}


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

def save_scan_safe(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper seguro de save_scan que nunca lanza excepciones.

    Uso esta función en el flujo del pipeline para que un fallo
    en Supabase no interrumpa la respuesta al usuario.
    """
    try:
        return save_scan(data)
    except Exception as exc:
        logger.error("Error inesperado en save_scan_safe: %s", exc)
        _fallback_offline(data)
        return {"saved": False, "reason": str(exc)}


# ---------------------------------------------------------------------------
# fetch_recent_scans — Sin cambios respecto a la versión original
# ---------------------------------------------------------------------------

def fetch_recent_scans(user_id: str, *, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Obtiene los últimos escaneos del usuario desde Supabase (tabla scan_results).

    Ordeno por created_at descendente si existe en la tabla; si la consulta falla
    (columna distinta), reintento sin orden y ordeno en Python por created_at/id.
    """
    if not user_id:
        return []

    try:
        client = _get_supabase_client()
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
        logger.warning("Listado reciente (order created_at) falló: %s", exc)

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
        logger.warning("No se pudieron listar escaneos recientes: %s", exc)
        return []


# ---------------------------------------------------------------------------
# sync_user — Sin cambios respecto a la versión original
# ---------------------------------------------------------------------------

def sync_user(user: Dict[str, Any]) -> None:
    """
    Sincroniza un usuario de Supabase Auth en la tabla users.

    Inserta el usuario si no existe (ON CONFLICT DO NOTHING).
    Nunca lanza excepciones al caller.

    Args:
        user: Dict con "id" (UUID) y "email" del usuario autenticado.
    """
    user_id = user.get("id")
    email = user.get("email", "")

    if not user_id:
        return

    try:
        client = _get_supabase_client()
        client.table("users").upsert(
            {"id": user_id, "email": email},
            on_conflict="id",
        ).execute()
        logger.debug("Usuario sincronizado: %s", email)
    except Exception as exc:
        # No bloqueo el flujo si falla sync de usuario
        logger.warning("Error sincronizando usuario: %s", exc)
