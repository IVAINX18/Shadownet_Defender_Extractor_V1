"""
backend/app/services/realtime_service.py — Monitoreo de procesos en tiempo real.

Uso psutil para listar procesos activos con métricas de CPU/memoria,
asignando un nivel de riesgo basado en análisis de comportamiento
y umbrales de consumo.

Nota sobre CPU: psutil.cpu_percent por proceso necesita dos lecturas separadas
en el tiempo; hago una pasada inicial y un sleep breve antes de medir para que
los valores no queden siempre en 0.

Mejoras de auditoría (Tarea 13):
  13.1 — Ordenar por CPU y seleccionar top-20 para análisis behavioral
  13.2 — _enrich_with_behavioral() con BehavioralShield.analyze_process(pid)
  13.3 — behavioral_risk_score, behavioral_is_suspicious, suspicious_actions, risk_reason
  13.4 — Diferenciación risk_reason: "behavioral" vs "performance"
  13.5 — Timeout global de 10s con concurrent.futures
  13.6 — Procesos con AccessDenied → risk_level="unknown", access_denied=True
"""

from __future__ import annotations

import concurrent.futures
import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("backend.realtime_service")

# Número de procesos top por CPU a analizar con BehavioralShield
_BEHAVIORAL_TOP_N = 20
# Timeout global para enriquecimiento behavioral (segundos)
_BEHAVIORAL_GLOBAL_TIMEOUT = 10


# ---------------------------------------------------------------------------
# 13.2 — Enriquecimiento con BehavioralShield
# ---------------------------------------------------------------------------

def _get_behavioral_shield():
    """Obtiene una instancia de BehavioralShield (lazy import)."""
    try:
        from core.dynamic.process_monitor import BehavioralShield
        return BehavioralShield()
    except Exception as exc:
        logger.debug("BehavioralShield no disponible: %s", exc)
        return None


def _enrich_with_behavioral(proc_dict: dict, shield) -> dict:
    """
    Enriquece un dict de proceso con análisis behavioral.

    Invoca BehavioralShield.analyze_process(pid) y añade:
    - behavioral_risk_score
    - behavioral_is_suspicious
    - suspicious_actions
    - risk_reason ("behavioral" | "performance" | None)

    13.4 — Diferenciación:
        - report.is_suspicious → risk_reason = "behavioral", risk_level = "suspicious"
        - cpu > 80 o memory > 80 → risk_reason = "performance"
        - ninguno → risk_reason = None

    Args:
        proc_dict: Diccionario con datos del proceso.
        shield: Instancia de BehavioralShield.

    Returns:
        proc_dict actualizado con campos behavioral.
    """
    try:
        report = shield.analyze_process(proc_dict["pid"])
        proc_dict["behavioral_risk_score"] = report.risk_score
        proc_dict["behavioral_is_suspicious"] = report.is_suspicious
        proc_dict["suspicious_actions"] = [
            {
                "description": getattr(a, "description", str(a)),
                "severity": getattr(a, "severity", ""),
                "ioc_type": getattr(a, "ioc_type", ""),
            }
            for a in getattr(report, "suspicious_actions", [])
        ]

        # 13.4 — Determinar risk_reason
        perf_suspicious = proc_dict.get("cpu", 0) > 80 or proc_dict.get("memory", 0) > 80

        if report.is_suspicious:
            proc_dict["risk_reason"] = "behavioral"
            proc_dict["risk_level"] = "suspicious"
        elif perf_suspicious:
            proc_dict["risk_reason"] = "performance"
        else:
            proc_dict["risk_reason"] = None

    except Exception as exc:
        logger.debug(
            "BehavioralShield falló para pid=%d: %s",
            proc_dict.get("pid", 0), exc,
        )
        proc_dict["behavioral_risk_score"] = 0.0
        proc_dict["behavioral_is_suspicious"] = False
        proc_dict["suspicious_actions"] = []
        proc_dict["risk_reason"] = None

    return proc_dict


def _enrich_top_processes(
    processes: List[Dict[str, Any]],
    shield,
    *,
    top_n: int = _BEHAVIORAL_TOP_N,
    timeout: float = _BEHAVIORAL_GLOBAL_TIMEOUT,
) -> List[Dict[str, Any]]:
    """
    Enriquece los top-N procesos por CPU con análisis behavioral.

    13.5 — Timeout global de 10s con concurrent.futures.
    Los procesos fuera del top-N reciben valores por defecto.

    Args:
        processes: Lista de procesos ya ordenados por CPU (descendente).
        shield: Instancia de BehavioralShield.
        top_n: Número de procesos a analizar.
        timeout: Timeout global en segundos.

    Returns:
        Lista de procesos actualizada con campos behavioral.
    """
    if shield is None:
        # Sin BehavioralShield → defaults para todos
        for p in processes:
            p.setdefault("behavioral_risk_score", 0.0)
            p.setdefault("behavioral_is_suspicious", False)
            p.setdefault("suspicious_actions", [])
            p.setdefault("risk_reason", "performance" if p.get("risk_level") == "suspicious" else None)
        return processes

    # Separar los top-N para análisis behavioral
    to_analyze = processes[:top_n]
    remaining = processes[top_n:]

    # 13.5 — ThreadPoolExecutor con timeout global
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(top_n, 8)) as executor:
            futures = {
                executor.submit(_enrich_with_behavioral, proc, shield): i
                for i, proc in enumerate(to_analyze)
            }

            done, not_done = concurrent.futures.wait(
                futures.keys(),
                timeout=timeout,
            )

            # Los que terminaron a tiempo ya están enriquecidos (mutación in-place)
            # Los que no terminaron reciben defaults
            for future in not_done:
                future.cancel()
                idx = futures[future]
                proc = to_analyze[idx]
                proc.setdefault("behavioral_risk_score", 0.0)
                proc.setdefault("behavioral_is_suspicious", False)
                proc.setdefault("suspicious_actions", [])
                proc.setdefault("risk_reason", None)
                logger.debug(
                    "BehavioralShield timeout para pid=%d", proc.get("pid", 0)
                )

    except Exception as exc:
        logger.warning("Error en enriquecimiento behavioral batch: %s", exc)
        for p in to_analyze:
            p.setdefault("behavioral_risk_score", 0.0)
            p.setdefault("behavioral_is_suspicious", False)
            p.setdefault("suspicious_actions", [])
            p.setdefault("risk_reason", None)

    # Los procesos fuera del top-N reciben defaults
    for p in remaining:
        p.setdefault("behavioral_risk_score", 0.0)
        p.setdefault("behavioral_is_suspicious", False)
        p.setdefault("suspicious_actions", [])
        p.setdefault("risk_reason", "performance" if p.get("risk_level") == "suspicious" else None)

    return to_analyze + remaining


# ---------------------------------------------------------------------------
# get_processes — API pública
# ---------------------------------------------------------------------------

def get_processes(*, top_n: int = 50) -> List[Dict[str, Any]]:
    """
    Lista los procesos activos del sistema con métricas de rendimiento
    y análisis behavioral para los top-20 por CPU.

    Retorno por proceso: pid, name, cpu (%), memory (% del sistema), memory_mb (RSS),
    risk_level, behavioral_risk_score, behavioral_is_suspicious, suspicious_actions,
    risk_reason, access_denied.
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
                "access_denied": False,
            })
        except (psutil.AccessDenied,) as exc:
            # 13.6 — AccessDenied → incluir con risk_level="unknown"
            try:
                pid = proc.pid
                name = proc.name() if hasattr(proc, "name") else "unknown"
            except Exception:
                pid = getattr(proc, "pid", 0)
                name = "unknown"

            processes.append({
                "pid": pid,
                "name": name,
                "cpu": 0.0,
                "cpu_percent": 0.0,
                "memory": 0.0,
                "memory_percent": 0.0,
                "memory_mb": 0.0,
                "risk_level": "unknown",
                "access_denied": True,
            })
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue

    # 13.1 — Ordenar por CPU descendente
    processes.sort(key=lambda p: p["cpu"], reverse=True)

    # Limitar al top_n total
    processes = processes[:top_n]

    # 13.1/13.2 — Enriquecer top-20 con análisis behavioral
    shield = _get_behavioral_shield()
    processes = _enrich_top_processes(processes, shield)

    return processes
