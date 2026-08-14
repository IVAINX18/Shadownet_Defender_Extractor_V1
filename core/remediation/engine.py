"""
core/remediation/engine.py — Motor de remediación de procesos maliciosos.

Implementa la terminación segura de procesos con verificaciones de seguridad:
  - Rechaza PIDs protegidos del SO (PID < 10 en Linux, sesión 0 en Windows)
  - Verifica exe_path antes de actuar para evitar terminaciones erróneas
  - Escalación gradual: SIGTERM → timeout 3s → SIGKILL
  - Captura PermissionError y psutil.AccessDenied sin propagar
  - Logging completo de toda operación para auditoría forense
"""
from __future__ import annotations

import os
import platform
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("core.remediation")


# ---------------------------------------------------------------------------
# Excepciones internas (no se propagan — se traducen a campos en Result)
# ---------------------------------------------------------------------------

class RemediationError(Exception):
    """Base exception para errores de remediación."""
    pass


class ProtectedProcessRejected(RemediationError):
    """Intento de terminar un proceso protegido del SO."""
    pass


class ExeMismatchRejected(RemediationError):
    """El exe_path real del proceso no coincide con expected_exe."""
    pass


# ---------------------------------------------------------------------------
# Result DTO
# ---------------------------------------------------------------------------

@dataclass
class TerminationResult:
    """Resultado de un intento de terminación de proceso."""
    success: bool
    pid: int
    method: str = ""          # "SIGTERM" | "SIGKILL" | "TerminateProcess" | ""
    error: Optional[str] = None   # PROTECTED_PROCESS_REJECTED | EXE_MISMATCH | ...
    exe_path: Optional[str] = None
    scan_id: Optional[str] = None
    reason: Optional[str] = None
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


# ---------------------------------------------------------------------------
# RemediationEngine
# ---------------------------------------------------------------------------

class RemediationEngine:
    """
    Motor de remediación segura de procesos maliciosos.

    Provee terminación de procesos con múltiples capas de protección:
    1. Validación de PID contra procesos protegidos del SO
    2. Verificación de exe_path si se provee expected_exe
    3. SIGTERM con timeout de 3s
    4. Escalación a SIGKILL si SIGTERM falla
    5. Captura de PermissionError sin propagar al caller
    """

    # PIDs que nunca deben terminarse (init, kernel threads, etc.)
    _MIN_SAFE_PID = 10
    _SIGTERM_TIMEOUT_SECONDS = 3

    def terminate_process(
        self,
        pid: int,
        reason: str,
        scan_id: str,
        *,
        expected_exe: Optional[Path] = None,
    ) -> TerminationResult:
        """
        Termina un proceso de forma segura.

        1. Verifica que el PID no sea un proceso protegido del SO.
        2. Si se provee expected_exe, verifica que el exe_path real coincida.
        3. Envía SIGTERM (Linux) o TerminateProcess (Windows) con timeout de 3s.
        4. Si no termina en 3s, escala a SIGKILL (Linux) o forced terminate.
        5. Captura PermissionError y psutil.AccessDenied sin propagar.

        Args:
            pid: ID del proceso a terminar.
            reason: Razón de la terminación (para logging/auditoría).
            scan_id: ID del escaneo que originó la acción.
            expected_exe: Ruta esperada del ejecutable (validación extra).

        Returns:
            TerminationResult con el resultado de la operación.
        """
        logger.info(
            "Remediación solicitada: pid=%d reason=%s scan_id=%s expected_exe=%s",
            pid, reason, scan_id, expected_exe,
        )

        # ── 1. Rechazar PIDs protegidos ────────────────────────────────
        try:
            self._validate_pid(pid)
        except ProtectedProcessRejected as exc:
            logger.warning("PID protegido rechazado: pid=%d — %s", pid, exc)
            return TerminationResult(
                success=False,
                pid=pid,
                error="PROTECTED_PROCESS_REJECTED",
                scan_id=scan_id,
                reason=reason,
            )

        # ── 2. Obtener información del proceso ────────────────────────
        try:
            import psutil
            proc = psutil.Process(pid)
            actual_exe = proc.exe()
        except (ImportError, Exception) as exc:
            # psutil no disponible o proceso no existe
            logger.error("No se pudo acceder al proceso pid=%d: %s", pid, exc)
            error_type = "PROCESS_NOT_FOUND"
            if isinstance(exc, ImportError):
                error_type = "PSUTIL_UNAVAILABLE"
            return TerminationResult(
                success=False,
                pid=pid,
                error=error_type,
                scan_id=scan_id,
                reason=reason,
            )

        # ── 3. Verificar exe_path si se provee expected_exe ───────────
        if expected_exe is not None:
            try:
                self._validate_exe_path(actual_exe, expected_exe)
            except ExeMismatchRejected as exc:
                logger.warning(
                    "Exe mismatch rechazado: pid=%d expected=%s actual=%s",
                    pid, expected_exe, actual_exe,
                )
                return TerminationResult(
                    success=False,
                    pid=pid,
                    error="EXE_MISMATCH",
                    exe_path=actual_exe,
                    scan_id=scan_id,
                    reason=reason,
                )

        # ── 4. Terminar proceso con escalación ────────────────────────
        return self._do_terminate(proc, pid, actual_exe, reason, scan_id)

    # ------------------------------------------------------------------
    # Validaciones internas
    # ------------------------------------------------------------------

    def _validate_pid(self, pid: int) -> None:
        """
        Rechaza PIDs protegidos del SO.

        Linux: PID < 10 (init, kernel threads, etc.)
        Windows: PID en sesión 0 (servicios del sistema)

        Raises:
            ProtectedProcessRejected si el PID es protegido.
        """
        if pid < self._MIN_SAFE_PID:
            raise ProtectedProcessRejected(
                f"PID {pid} es un proceso protegido del SO (PID < {self._MIN_SAFE_PID})"
            )

        # Windows: rechazar procesos de la sesión 0 (servicios del sistema)
        if platform.system() == "Windows":
            try:
                import psutil
                proc = psutil.Process(pid)
                # En Windows, session_id == 0 son servicios del sistema
                if hasattr(proc, "session_id") and callable(getattr(proc, "session_id", None)):
                    if proc.session_id() == 0:
                        raise ProtectedProcessRejected(
                            f"PID {pid} pertenece a la sesión 0 (servicio del sistema Windows)"
                        )
            except ProtectedProcessRejected:
                raise
            except Exception:
                pass  # No podemos verificar → no rechazar por este motivo

    def _validate_exe_path(self, actual_exe: str, expected_exe: Path) -> None:
        """
        Verifica que el exe_path real del proceso coincida con expected_exe.

        Raises:
            ExeMismatchRejected si no coinciden.
        """
        try:
            actual_resolved = str(Path(actual_exe).resolve()).lower()
            expected_resolved = str(expected_exe.resolve()).lower()
            if actual_resolved != expected_resolved:
                raise ExeMismatchRejected(
                    f"exe_path real '{actual_exe}' no coincide con "
                    f"expected '{expected_exe}'"
                )
        except ExeMismatchRejected:
            raise
        except Exception as exc:
            raise ExeMismatchRejected(f"No se pudo comparar exe_paths: {exc}")

    # ------------------------------------------------------------------
    # Terminación con escalación
    # ------------------------------------------------------------------

    def _do_terminate(
        self,
        proc,  # psutil.Process
        pid: int,
        exe_path: str,
        reason: str,
        scan_id: str,
    ) -> TerminationResult:
        """
        Ejecuta la terminación del proceso con escalación gradual.

        1. SIGTERM / TerminateProcess con timeout 3s
        2. Si no termina → SIGKILL / forced terminate
        3. Captura PermissionError y AccessDenied sin propagar
        """
        import psutil

        is_windows = platform.system() == "Windows"

        # ── Paso 1: SIGTERM (o TerminateProcess en Windows) ───────────
        try:
            if is_windows:
                proc.terminate()  # psutil usa TerminateProcess en Windows
                method = "TerminateProcess"
            else:
                os.kill(pid, signal.SIGTERM)
                method = "SIGTERM"

            logger.info(
                "Señal %s enviada a pid=%d exe=%s reason=%s scan_id=%s",
                method, pid, exe_path, reason, scan_id,
            )

            # Esperar terminación con timeout
            try:
                proc.wait(timeout=self._SIGTERM_TIMEOUT_SECONDS)
                logger.info(
                    "Proceso pid=%d terminado exitosamente con %s",
                    pid, method,
                )
                return TerminationResult(
                    success=True,
                    pid=pid,
                    method=method,
                    exe_path=exe_path,
                    scan_id=scan_id,
                    reason=reason,
                )
            except psutil.TimeoutExpired:
                logger.warning(
                    "Proceso pid=%d no terminó en %ds con %s, escalando...",
                    pid, self._SIGTERM_TIMEOUT_SECONDS, method,
                )

        except (PermissionError, psutil.AccessDenied) as exc:
            logger.error(
                "Permiso denegado al enviar %s a pid=%d: %s",
                "TerminateProcess" if is_windows else "SIGTERM", pid, exc,
            )
            return TerminationResult(
                success=False,
                pid=pid,
                method="SIGTERM" if not is_windows else "TerminateProcess",
                error="PERMISSION_DENIED",
                exe_path=exe_path,
                scan_id=scan_id,
                reason=reason,
            )
        except psutil.NoSuchProcess:
            # Proceso ya terminó entre la verificación y el signal
            logger.info("Proceso pid=%d ya no existe (terminó antes del signal)", pid)
            return TerminationResult(
                success=True,
                pid=pid,
                method="already_terminated",
                exe_path=exe_path,
                scan_id=scan_id,
                reason=reason,
            )
        except Exception as exc:
            logger.error("Error inesperado al enviar SIGTERM a pid=%d: %s", pid, exc)
            return TerminationResult(
                success=False,
                pid=pid,
                error=f"SIGTERM_FAILED: {exc}",
                exe_path=exe_path,
                scan_id=scan_id,
                reason=reason,
            )

        # ── Paso 2: SIGKILL (escalación forzada) ─────────────────────
        try:
            if is_windows:
                proc.kill()  # En Windows, kill() es más agresivo
                method = "TerminateProcess_forced"
            else:
                os.kill(pid, signal.SIGKILL)
                method = "SIGKILL"

            logger.warning(
                "Escalación %s a pid=%d exe=%s reason=%s scan_id=%s",
                method, pid, exe_path, reason, scan_id,
            )

            proc.wait(timeout=5)  # Esperar finalización después de SIGKILL
            logger.info("Proceso pid=%d terminado con %s (escalado)", pid, method)

            return TerminationResult(
                success=True,
                pid=pid,
                method=method,
                exe_path=exe_path,
                scan_id=scan_id,
                reason=reason,
            )

        except (PermissionError, psutil.AccessDenied) as exc:
            logger.error(
                "Permiso denegado al enviar %s a pid=%d: %s",
                method, pid, exc,
            )
            return TerminationResult(
                success=False,
                pid=pid,
                method=method,
                error="PERMISSION_DENIED",
                exe_path=exe_path,
                scan_id=scan_id,
                reason=reason,
            )
        except psutil.NoSuchProcess:
            logger.info("Proceso pid=%d terminó durante escalación", pid)
            return TerminationResult(
                success=True,
                pid=pid,
                method=method,
                exe_path=exe_path,
                scan_id=scan_id,
                reason=reason,
            )
        except Exception as exc:
            logger.error("Error inesperado al enviar %s a pid=%d: %s", method, pid, exc)
            return TerminationResult(
                success=False,
                pid=pid,
                method=method,
                error=f"KILL_FAILED: {exc}",
                exe_path=exe_path,
                scan_id=scan_id,
                reason=reason,
            )
