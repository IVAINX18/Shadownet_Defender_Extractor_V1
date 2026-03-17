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
from typing import Any, Dict, Optional

logger = logging.getLogger("backend.supabase")

# ---------------------------------------------------------------------------
# URL de Supabase — La KEY se lee desde variable de entorno
# ---------------------------------------------------------------------------
SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    "https://cvygqntdjntvweisvssc.supabase.co",
)
SUPABASE_TABLE = "scan_results"


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
    # Extraigo solo los campos que necesito persistir
    record = {
        "file_name": str(data.get("file_name", "unknown")),
        "result": str(data.get("result", "benign")),
        "confidence": float(data.get("confidence", 0.0)),
        "risk_level": str(data.get("risk_level", "low")),
        "explanation": data.get("explanation"),
        "scan_time": str(data.get("scan_time", "0.00s")),
        "timestamp": data.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat(),
        ),
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
