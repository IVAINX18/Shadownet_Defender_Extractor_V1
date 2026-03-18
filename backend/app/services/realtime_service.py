"""
backend/app/services/realtime_service.py — Monitoreo de procesos en tiempo real.

Uso psutil para listar procesos activos con métricas de CPU y memoria,
asignando un nivel de riesgo básico según umbrales de consumo.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger("backend.realtime_service")


def get_processes(*, top_n: int = 50) -> List[Dict[str, Any]]:
    """
    Lista los procesos activos del sistema con métricas de rendimiento.

    Uso psutil.process_iter() para iterar de forma segura sobre los procesos.
    Si un proceso desaparece durante la iteración, lo omito silenciosamente.

    Args:
        top_n: Número máximo de procesos a retornar (los de mayor CPU).

    Returns:
        Lista de dicts con pid, name, cpu, memory y risk_level.
    """
    try:
        import psutil
    except ImportError:
        logger.error("psutil no está instalado. Instálalo con: pip install psutil")
        raise ImportError(
            "El paquete 'psutil' es requerido para monitoreo en tiempo real. "
            "Instálalo con: pip install psutil"
        )

    processes: List[Dict[str, Any]] = []

    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            pid = info.get("pid", 0)
            name = info.get("name", "unknown")
            cpu = info.get("cpu_percent", 0.0) or 0.0
            memory = info.get("memory_percent", 0.0) or 0.0

            # Asigno riesgo básico según umbrales de consumo
            if cpu > 80 or memory > 80:
                risk_level = "suspicious"
            else:
                risk_level = "benign"

            processes.append({
                "pid": pid,
                "name": name,
                "cpu": round(cpu, 2),
                "memory": round(memory, 2),
                "risk_level": risk_level,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Ordeno por CPU descendente y limito
    processes.sort(key=lambda p: p["cpu"], reverse=True)
    return processes[:top_n]
