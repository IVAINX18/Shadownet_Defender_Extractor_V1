"""
backend/app/integrations/supabase_client.py — Cliente Supabase para persistencia.

Implemento la integración con Supabase para guardar los resultados de
escaneo según el PRD sección 8. Leo las credenciales desde variables
de entorno para no hardcodear secrets.

Tabla esperada en Supabase: scan_results
Campos: file_name, result, confidence, risk_level, explanation,
        scan_time, timestamp
"""

from __future__ import annotations

import logging
import os
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


def save_scan(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Guarda un resultado de escaneo en Supabase.

    Persisto los campos definidos en el PRD sección 8:
    - file_name
    - result (benign | suspicious | malicious)
    - confidence (float)
    - risk_level (low | medium | high)
    - explanation (text, puede ser null)
    - scan_time (string)
    - timestamp (ISO8601)

    Args:
        data: Diccionario con los campos del resultado de escaneo.
              Acepto tanto ScanResult.model_dump() como un dict manual.

    Returns:
        Diccionario con la respuesta de Supabase (registro insertado).

    Raises:
        RuntimeError: Si SUPABASE_KEY no está configurada o la inserción falla.
    """
    # Extraigo los campos que persisto según el esquema de Supabase
    record = {
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
        "metadata": {
            k: v for k, v in data.items()
            if k in ("features_detected", "timestamp")
        },
    }

    try:
        client = _get_supabase_client()
        response = (
            client.table(SUPABASE_TABLE)
            .insert(record)
            .execute()
        )
        logger.info(
            "Resultado guardado en Supabase: %s → %s",
            record["file_name"],
            record["result"],
        )
        return {"saved": True, "record": record}

    except RuntimeError as exc:
        # SUPABASE_KEY no configurada — logueo pero no bloqueo el flujo
        logger.warning("Supabase no disponible: %s", exc)
        return {"saved": False, "reason": str(exc)}

    except ImportError as exc:
        # Paquete supabase no instalado
        logger.warning("Supabase no instalado: %s", exc)
        return {"saved": False, "reason": str(exc)}

    except Exception as exc:
        # Error de red, permisos, etc. — no bloqueo el escaneo por esto
        logger.error("Error guardando en Supabase: %s", exc)
        return {"saved": False, "reason": str(exc)}


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
        return {"saved": False, "reason": str(exc)}


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

