"""
backend/app/services/realtime_service.py — Monitoreo de procesos en tiempo real.

Uso psutil para listar procesos activos con métricas de CPU/memoria,
asignando un nivel de riesgo básico según umbrales de consumo.

Nota sobre CPU: psutil.cpu_percent por proceso necesita dos lecturas separadas
en el tiempo; hago una pasada inicial y un sleep breve antes de medir para que
los valores no queden siempre en 0.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

logger = logging.getLogger("backend.realtime_service")


def get_processes(*, top_n: int = 50) -> List[Dict[str, Any]]:
    """
    Lista los procesos activos del sistema con métricas de rendimiento.

    Retorno por proceso: pid, name, cpu (%), memory (% del sistema), memory_mb (RSS),
    risk_level (benign | suspicious según umbrales de CPU/memoria %).
    """
    try:
        import psutil
    except ImportError:
        logger.error("psutil no está instalado. Instálalo con: pip install psutil")
        raise ImportError(
            "El paquete 'psutil' es requerido para monitoreo en tiempo real. "
            "Instálalo con: pip install psutil"
        )

    candidates: List[Any] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            proc.cpu_percent(interval=None)
            candidates.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    time.sleep(0.12)

    processes: List[Dict[str, Any]] = []
    for proc in candidates:
        try:
            cpu = float(proc.cpu_percent(interval=None) or 0.0)
            mem_pct = float(proc.memory_percent() or 0.0)
            rss = proc.memory_info().rss
            memory_mb = round(rss / (1024 * 1024), 2)
            pid = proc.pid
            name = proc.name() or "unknown"

            if cpu > 80 or mem_pct > 80:
                risk_level = "suspicious"
            else:
                risk_level = "benign"

            processes.append({
                "pid": pid,
                "name": name,
                "cpu": round(cpu, 2),
                "cpu_percent": round(cpu, 2),
                "memory": round(mem_pct, 2),
                "memory_percent": round(mem_pct, 2),
                "memory_mb": memory_mb,
                "risk_level": risk_level,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    processes.sort(key=lambda p: p["cpu"], reverse=True)
    return processes[:top_n]
