"""
backend/app/services/offline_service.py — Cola offline para resiliencia.

Cuando Supabase o la red no están disponibles, almaceno los resultados
de escaneo en una cola local (archivo JSON) para sincronizarlos después.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("backend.offline_service")

# Archivo de cola persistente — se almacena junto al proyecto
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_QUEUE_FILE = _PROJECT_ROOT / "data" / "offline_queue.json"


def _ensure_queue_dir() -> None:
    """Crea el directorio de la cola si no existe."""
    _QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)


def _load_queue() -> List[Dict[str, Any]]:
    """Lee la cola desde disco."""
    if not _QUEUE_FILE.exists():
        return []
    try:
        data = json.loads(_QUEUE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Error leyendo cola offline: %s", exc)
        return []


def _save_queue(queue: List[Dict[str, Any]]) -> None:
    """Escribe la cola a disco."""
    _ensure_queue_dir()
    try:
        _QUEUE_FILE.write_text(
            json.dumps(queue, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
    except OSError as exc:
        logger.error("Error guardando cola offline: %s", exc)


def is_online() -> bool:
    """
    Verifica si Supabase está accesible.

    Intento una operación mínima. Si falla por cualquier razón
    (red, key, paquete), considero que estamos offline.
    """
    supabase_key = os.getenv("SUPABASE_KEY", "").strip()
    if not supabase_key:
        return False

    try:
        import requests
        from backend.app.integrations.supabase_client import SUPABASE_URL
        resp = requests.head(SUPABASE_URL, timeout=3)
        return resp.status_code < 500
    except Exception:
        return False


def queue_scan(scan_result: Dict[str, Any]) -> None:
    """
    Agrega un resultado de escaneo a la cola offline.

    Args:
        scan_result: Dict con los campos del ScanResult.
    """
    queue = _load_queue()
    entry = {
        **scan_result,
        "offline": True,
        "queued_at": datetime.now(timezone.utc).isoformat(),
    }
    queue.append(entry)
    _save_queue(queue)
    logger.info(
        "Resultado encolado offline: %s (%d pendientes)",
        scan_result.get("file_name", "unknown"),
        len(queue),
    )


def get_queue_size() -> int:
    """Retorna la cantidad de items pendientes en la cola."""
    return len(_load_queue())


def sync_queue() -> Dict[str, Any]:
    """
    Intenta enviar todos los resultados pendientes a Supabase.

    Returns:
        Dict con synced (int), failed (int), remaining (int).
    """
    queue = _load_queue()
    if not queue:
        return {"synced": 0, "failed": 0, "remaining": 0}

    if not is_online():
        logger.warning("Sync abortado: Supabase no accesible")
        return {"synced": 0, "failed": 0, "remaining": len(queue)}

    from backend.app.integrations.supabase_client import save_scan

    synced = 0
    failed = 0
    remaining: List[Dict[str, Any]] = []

    for item in queue:
        try:
            # Quito campos de cola antes de enviar
            to_save = {k: v for k, v in item.items() if k not in ("queued_at",)}
            to_save["offline"] = True  # Marco que fue guardado offline
            result = save_scan(to_save)
            if result.get("saved"):
                synced += 1
            else:
                remaining.append(item)
                failed += 1
        except Exception as exc:
            logger.error("Error sincronizando item: %s", exc)
            remaining.append(item)
            failed += 1

    _save_queue(remaining)
    logger.info("Sync completado: %d enviados, %d fallidos, %d pendientes", synced, failed, len(remaining))
    return {"synced": synced, "failed": failed, "remaining": len(remaining)}
