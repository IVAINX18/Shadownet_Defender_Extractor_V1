"""
core/dynamic/process_monitor.py — Escudo de Comportamiento Activo.

Cuando el análisis estático no es suficiente (malware ofuscado, APIs
resueltas en runtime, polimorfismo), este módulo analiza el comportamiento
de los procesos activos del sistema en tiempo real.

* PARA JUNIORS — ¿Por qué análisis dinámico?
    Un troyano como njRAT puede tener TODAS sus funciones cargadas dinámicamente
    con LoadLibrary + GetProcAddress. El extractor estático nunca verá "WinExec"
    o "CreateRemoteThread" en la IAT. Sin embargo, una vez ejecutado, el proceso
    SÍ abrirá conexiones de red a IPs de Comando & Control (C2), spawneará
    subprocesos, e intentará escribir en %AppData%\\Roaming\\.

    El BehavioralShield monitorea ESTAS acciones en tiempo real para detectar
    malware que ha escapado del análisis estático.

Indicadores de Compromiso (IoC) que monitoreamos:
    1. Conexiones de red hacia IPs/puertos asociados a botnets y C2
    2. Creación excesiva de procesos hijos (técnica de evasión "spawning")
    3. Consumo anormal sostenido de CPU (ransomware cifrando, miners)
    4. Escritura en directorios críticos del sistema (persistencia)
    5. Acceso a memoria de otros procesos (process injection)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import setup_logger

logger = setup_logger(__name__)


@dataclass
class SuspiciousAction:
    """Registro de una actividad sospechosa detectada."""
    description: str
    severity: float  # 0.0 - 1.0 (contribución al score de riesgo)
    ioc_type: str    # "network", "process", "cpu", "filesystem", "injection"


@dataclass
class BehaviorReport:
    """Reporte completo del análisis de comportamiento de un proceso."""
    pid: int
    process_name: str
    risk_score: float
    suspicious_actions: List[SuspiciousAction] = field(default_factory=list)
    is_suspicious: bool = False
    scan_time_ms: float = 0.0
    error: Optional[str] = None

    def summary(self) -> str:
        """Resumen legible del reporte."""
        if not self.suspicious_actions:
            return f"PID {self.pid} ({self.process_name}): Sin actividad sospechosa"
        actions = "; ".join(a.description for a in self.suspicious_actions)
        return f"PID {self.pid} ({self.process_name}) | Score: {self.risk_score:.2f} | {actions}"


class BehavioralShield:
    """
    Monitor de comportamiento de procesos en tiempo real.

    Analiza procesos activos buscando indicadores de comportamiento
    típico de troyanos, spyware, worms y ransomware.

    Uso básico:
        shield = BehavioralShield()
        report = shield.analyze_process(pid=1234)
        if report.is_suspicious:
            print(report.summary())

    Uso en monitoreo continuo:
        for proc_info in shield.scan_all_processes():
            if proc_info.is_suspicious:
                alert(proc_info)
    """

    # ------------------------------------------------------------------
    # Configuración de umbrales y firmas de IoC
    # ------------------------------------------------------------------

    # Prefijos de IP asociados a infraestructura de C2 y botnets conocidos.
    # ⚠️ Esta lista es representativa — en producción se debe integrar con
    # feeds de inteligencia de amenazas (ThreatFox, AbuseCH, etc.)
    SUSPICIOUS_IP_PREFIXES: List[str] = [
        "185.220.",  # Tor exit nodes / C2 conocidos
        "45.142.",   # Bulletproof hosting usado por RATs
        "194.165.",  # Hosting asociado a botnets
        "5.188.",    # Infraestructura de malware conocida
    ]

    # Puertos típicos de C2 de troyanos conocidos
    SUSPICIOUS_PORTS: List[int] = [
        1177,   # njRAT
        4444,   # Metasploit reverse shell
        5900,   # VNC (acceso remoto no autorizado)
        8080,   # Puerto alternativo de C2 HTTP
        31337,  # Puerto "eleet" clásico de backdoors
        6667,   # IRC botnet C2
    ]

    # Directorios de sistema donde el malware suele escribir para persistencia
    SUSPICIOUS_WRITE_DIRS: List[str] = [
        "/etc/cron",
        "/etc/init.d",
        "/etc/systemd",
        "\\AppData\\Roaming",
        "\\Windows\\System32",
        "\\Windows\\SysWOW64",
        "\\Startup",
    ]

    # Nombres de proceso que el malware suele usar para camuflarse
    SUSPICIOUS_PROCESS_NAMES: List[str] = [
        "svchost32",     # Falso svchost de 32-bit
        "csrss32",       # Falso csrss
        "lsass32",       # Falso lsass
        "taskhost32",    # Falso taskhost
        "winlogon32",    # Falso winlogon
    ]

    # Umbrales de comportamiento
    MAX_CHILD_PROCESSES = 8       # Más de esto es sospechoso
    CPU_ALERT_THRESHOLD = 80.0    # % de CPU sostenido sospechoso
    CPU_SAMPLE_INTERVAL = 0.5     # Segundos para medir CPU

    def __init__(self) -> None:
        self._psutil_available = self._check_psutil()

    # ------------------------------------------------------------------
    # API Pública
    # ------------------------------------------------------------------

    def analyze_process(self, pid: int) -> BehaviorReport:
        """
        Analiza un proceso específico por comportamiento sospechoso.

        Args:
            pid: ID del proceso a analizar.

        Returns:
            BehaviorReport con el score de riesgo y acciones detectadas.
        """
        if not self._psutil_available:
            return BehaviorReport(
                pid=pid, process_name="?", risk_score=0.0,
                error="psutil no disponible"
            )

        import psutil
        start = time.perf_counter()

        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
        except psutil.NoSuchProcess:
            return BehaviorReport(pid=pid, process_name="?", risk_score=0.0,
                                  error="Proceso no encontrado")
        except psutil.AccessDenied:
            return BehaviorReport(pid=pid, process_name="?", risk_score=0.0,
                                  error="Acceso denegado")

        actions: List[SuspiciousAction] = []

        # Ejecutar todos los checks
        self._check_network(proc, actions)
        self._check_child_processes(proc, actions)
        self._check_cpu(proc, actions)
        self._check_process_name(proc_name, actions)
        self._check_open_files(proc, actions)

        # Calcular score total (normalizado a [0.0, 1.0])
        risk_score = min(1.0, sum(a.severity for a in actions))
        elapsed_ms = (time.perf_counter() - start) * 1000

        report = BehaviorReport(
            pid=pid,
            process_name=proc_name,
            risk_score=round(risk_score, 4),
            suspicious_actions=actions,
            is_suspicious=risk_score >= 0.3,
            scan_time_ms=round(elapsed_ms, 2),
        )

        if report.is_suspicious:
            logger.warning("Comportamiento sospechoso: %s", report.summary())

        return report

    def scan_all_processes(self, min_risk: float = 0.3) -> List[BehaviorReport]:
        """
        Escanea todos los procesos activos del sistema.

        Args:
            min_risk: Score mínimo para incluir un proceso en el resultado.

        Returns:
            Lista de BehaviorReport de los procesos con riesgo >= min_risk.
        """
        if not self._psutil_available:
            logger.error("psutil no disponible. El monitoreo dinámico no funcionará.")
            return []

        import psutil
        suspicious_reports: List[BehaviorReport] = []

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                report = self.analyze_process(proc.info["pid"])
                if report.risk_score >= min_risk and report.error is None:
                    suspicious_reports.append(report)
            except Exception:
                continue

        if suspicious_reports:
            logger.warning(
                "Monitoreo dinámico: %d proceso(s) con comportamiento sospechoso detectados.",
                len(suspicious_reports)
            )

        return suspicious_reports

    def get_process_telemetry(self, pid: int) -> Dict:
        """
        Retorna telemetría bruta de un proceso para la API de /scan/realtime.

        Returns:
            Diccionario con métricas de CPU, memoria, red y archivos abiertos.
        """
        if not self._psutil_available:
            return {"pid": pid, "error": "psutil no disponible"}

        import psutil
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                mem = proc.memory_info()
                cpu = proc.cpu_percent(interval=0.1)
                connections = proc.connections(kind="inet")
                children = proc.children()

            return {
                "pid": pid,
                "name": proc.name(),
                "cpu_percent": cpu,
                "memory_mb": round(mem.rss / 1024 / 1024, 2),
                "open_connections": len(connections),
                "child_processes": len(children),
                "status": proc.status(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return {"pid": pid, "error": str(exc)}

    # ------------------------------------------------------------------
    # Checks Privados de Comportamiento
    # ------------------------------------------------------------------

    def _check_network(self, proc, actions: List[SuspiciousAction]) -> None:
        """Detecta conexiones de red hacia IPs/puertos sospechosos de C2."""
        import psutil
        try:
            connections = proc.connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return

        for conn in connections:
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            # Verificar IP contra lista de prefijos sospechosos
            for prefix in self.SUSPICIOUS_IP_PREFIXES:
                if remote_ip.startswith(prefix):
                    actions.append(SuspiciousAction(
                        description=f"Conexión C2 establecida hacia {remote_ip}:{remote_port}",
                        severity=0.5,
                        ioc_type="network",
                    ))
                    break

            # Verificar puerto sospechoso
            if remote_port in self.SUSPICIOUS_PORTS:
                actions.append(SuspiciousAction(
                    description=f"Conexión a puerto de backdoor conocido: {remote_port}",
                    severity=0.4,
                    ioc_type="network",
                ))

    def _check_child_processes(self, proc, actions: List[SuspiciousAction]) -> None:
        """Detecta spawn excesivo de subprocesos (técnica de evasión de RATs y worms)."""
        import psutil
        try:
            children = proc.children(recursive=True)
            child_count = len(children)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return

        if child_count > self.MAX_CHILD_PROCESSES:
            actions.append(SuspiciousAction(
                description=f"Spawn excesivo de subprocesos: {child_count} procesos hijos",
                severity=min(0.3, child_count * 0.02),
                ioc_type="process",
            ))

    def _check_cpu(self, proc, actions: List[SuspiciousAction]) -> None:
        """Detecta consumo anormal de CPU (ransomware cifrando, cryptominer)."""
        import psutil
        try:
            cpu = proc.cpu_percent(interval=self.CPU_SAMPLE_INTERVAL)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return

        if cpu > self.CPU_ALERT_THRESHOLD:
            actions.append(SuspiciousAction(
                description=f"Consumo anormal de CPU: {cpu:.1f}% (posible miner/ransomware)",
                severity=0.25,
                ioc_type="cpu",
            ))

    def _check_process_name(self, proc_name: str, actions: List[SuspiciousAction]) -> None:
        """Detecta procesos que se camuflan como procesos legítimos del sistema."""
        name_lower = proc_name.lower()
        for suspicious_name in self.SUSPICIOUS_PROCESS_NAMES:
            if suspicious_name.lower() in name_lower:
                actions.append(SuspiciousAction(
                    description=f"Nombre de proceso sospechoso (camuflaje): '{proc_name}'",
                    severity=0.35,
                    ioc_type="process",
                ))
                break

    def _check_open_files(self, proc, actions: List[SuspiciousAction]) -> None:
        """Detecta acceso a directorios críticos del sistema (persistencia)."""
        import psutil
        try:
            open_files = proc.open_files()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return

        for file_info in open_files:
            file_path_str = str(file_info.path)
            for suspicious_dir in self.SUSPICIOUS_WRITE_DIRS:
                if suspicious_dir.lower() in file_path_str.lower():
                    actions.append(SuspiciousAction(
                        description=f"Acceso a directorio crítico del sistema: {file_path_str}",
                        severity=0.3,
                        ioc_type="filesystem",
                    ))
                    break

    @staticmethod
    def _check_psutil() -> bool:
        """Verifica si psutil está disponible."""
        try:
            import psutil  # noqa: F401
            return True
        except ImportError:
            logger.error(
                "psutil no está instalado. El monitoreo dinámico estará deshabilitado. "
                "Instalar con: pip install psutil"
            )
            return False
