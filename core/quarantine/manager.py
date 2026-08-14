"""
core/quarantine/manager.py — Módulo de cuarentena segura de archivos maliciosos.

Proporciona QuarantineManager para aislar archivos detectados como amenazas,
preservando su integridad forense y eliminando sus permisos de ejecución.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class QuarantineResult:
    """Resultado de una operación de cuarentena."""
    success: bool
    quarantine_path: Optional[Path]
    sha256: str
    meta_path: Optional[Path]
    error: Optional[str]  # SYMLINK_REJECTED | PATH_TRAVERSAL_REJECTED | etc.


@dataclass
class RestoreResult:
    """Resultado de una operación de restauración desde cuarentena."""
    success: bool
    destination: Optional[Path]
    integrity_ok: bool
    error: Optional[str]


def _compute_sha256(file_path: Path) -> str:
    """Calcula SHA-256 de un archivo en chunks de 64 KB."""
    sha256 = hashlib.sha256()
    chunk_size = 64 * 1024
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def _remove_exec_permission(file_path: Path) -> None:
    """Elimina permisos de ejecución del archivo de forma multiplataforma."""
    if platform.system() == "Windows":
        try:
            import ctypes
            import stat as _stat
            # Quitar atributo de ejecución en Windows vía ctypes
            FILE_ATTRIBUTE_READONLY = 0x1
            ctypes.windll.kernel32.SetFileAttributesW(str(file_path), FILE_ATTRIBUTE_READONLY)
        except Exception as exc:
            logger.warning("No se pudo eliminar atributo ejecutable en Windows: %s", exc)
    else:
        try:
            import stat
            current = file_path.stat().st_mode
            # Quitar bits de ejecución para owner, group y others
            new_mode = current & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            file_path.chmod(new_mode)
        except Exception as exc:
            logger.warning("No se pudo hacer chmod a-x en %s: %s", file_path, exc)


class QuarantineManager:
    """
    Gestor de cuarentena segura para archivos maliciosos detectados.

    Mueve archivos a un directorio seguro, les elimina permisos de ejecución
    y guarda metadatos forenses en archivos JSON adyacentes.
    """

    def __init__(self, quarantine_dir: Optional[Path] = None) -> None:
        if quarantine_dir is None:
            from configs.settings import QUARANTINE_DIR
            quarantine_dir = QUARANTINE_DIR
        self.quarantine_dir = Path(quarantine_dir)

    def _ensure_quarantine_dir(self) -> None:
        """Crea el directorio de cuarentena con permisos restrictivos (700)."""
        if not self.quarantine_dir.exists():
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            if platform.system() != "Windows":
                try:
                    import stat
                    self.quarantine_dir.chmod(stat.S_IRWXU)  # 700
                except Exception as exc:
                    logger.warning("No se pudo fijar permisos 700 en %s: %s", self.quarantine_dir, exc)
            logger.info("Directorio de cuarentena creado: %s", self.quarantine_dir)

    def quarantine_file(
        self,
        file_path: Path,
        scan_result: Dict[str, Any],
        *,
        actor: str = "system",
    ) -> QuarantineResult:
        """
        Mueve file_path a QUARANTINE_DIR con nombre {SHA256[:8]}_{timestamp}.quar.

        Args:
            file_path: Ruta al archivo a cuarentenar.
            scan_result: Resumen del resultado de escaneo (para metadatos).
            actor: Identificador del usuario/sistema que inició la operación.

        Returns:
            QuarantineResult con el estado de la operación.
        """
        file_path = Path(file_path)

        # ── Rechazo de symlinks (TOCTOU protection) ───────────────────
        if file_path.is_symlink():
            logger.warning("Cuarentena rechazada (symlink): %s", file_path)
            return QuarantineResult(
                success=False,
                quarantine_path=None,
                sha256="",
                meta_path=None,
                error="SYMLINK_REJECTED",
            )

        # ── Rechazo de path traversal ─────────────────────────────────
        try:
            resolved = file_path.resolve()
        except Exception:
            resolved = file_path
        # Detectar componentes ".." en el path original
        if ".." in file_path.parts or ".." in str(file_path):
            logger.warning("Cuarentena rechazada (path traversal): %s", file_path)
            return QuarantineResult(
                success=False,
                quarantine_path=None,
                sha256="",
                meta_path=None,
                error="PATH_TRAVERSAL_REJECTED",
            )

        if not file_path.exists():
            return QuarantineResult(
                success=False,
                quarantine_path=None,
                sha256="",
                meta_path=None,
                error="FILE_NOT_FOUND",
            )

        # ── Calcular SHA-256 ANTES de mover ───────────────────────────
        try:
            sha256 = _compute_sha256(file_path)
        except Exception as exc:
            logger.error("Error calculando SHA-256 de %s: %s", file_path, exc)
            return QuarantineResult(
                success=False,
                quarantine_path=None,
                sha256="",
                meta_path=None,
                error=f"SHA256_ERROR: {exc}",
            )

        self._ensure_quarantine_dir()

        # ── Generar nombre de cuarentena ──────────────────────────────
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        base_name = f"{sha256[:8]}_{timestamp}"
        quar_path = self.quarantine_dir / f"{base_name}.quar"
        meta_path = self.quarantine_dir / f"{base_name}.meta.json"

        # ── Mover archivo ─────────────────────────────────────────────
        try:
            shutil.move(str(file_path), str(quar_path))
        except Exception as exc:
            logger.error("Error moviendo %s a cuarentena: %s", file_path, exc)
            return QuarantineResult(
                success=False,
                quarantine_path=None,
                sha256=sha256,
                meta_path=None,
                error=f"MOVE_ERROR: {exc}",
            )

        # ── Eliminar permisos de ejecución ────────────────────────────
        _remove_exec_permission(quar_path)

        # ── Crear archivo de metadatos ────────────────────────────────
        meta = {
            "original_path": str(file_path),
            "sha256": sha256,
            "file_size": quar_path.stat().st_size,
            "quarantine_path": str(quar_path),
            "quarantine_timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_result": {
                "result": scan_result.get("result", ""),
                "risk_level": scan_result.get("risk_level", ""),
                "operational_status": scan_result.get("operational_status", ""),
                "scan_id": scan_result.get("scan_id", ""),
            },
            "actor": actor,
        }
        try:
            meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("No se pudo escribir metadatos de cuarentena: %s", exc)

        logger.info(
            "Archivo cuarentenado: original=%s | sha256=%s | dest=%s | actor=%s",
            file_path,
            sha256,
            quar_path,
            actor,
        )

        return QuarantineResult(
            success=True,
            quarantine_path=quar_path,
            sha256=sha256,
            meta_path=meta_path,
            error=None,
        )

    def restore_file(
        self,
        quarantine_path: Path,
        destination: Path,
    ) -> RestoreResult:
        """
        Restaura un archivo desde cuarentena al destino indicado,
        verificando la integridad SHA-256.

        Args:
            quarantine_path: Ruta al archivo .quar en cuarentena.
            destination: Ruta de destino donde restaurar el archivo.

        Returns:
            RestoreResult con el estado e integridad de la restauración.
        """
        quarantine_path = Path(quarantine_path)
        destination = Path(destination)

        if not quarantine_path.exists():
            return RestoreResult(
                success=False,
                destination=None,
                integrity_ok=False,
                error="QUARANTINE_FILE_NOT_FOUND",
            )

        # ── Leer SHA-256 esperado del .meta.json ──────────────────────
        meta_path = quarantine_path.with_suffix("").with_suffix(".meta.json")
        # Handle double extension: abc12345_20240101T000000.quar → abc12345_20240101T000000.meta.json
        stem = quarantine_path.stem  # abc12345_20240101T000000
        meta_path = quarantine_path.parent / f"{stem}.meta.json"
        expected_sha256: Optional[str] = None
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                expected_sha256 = meta.get("sha256")
            except Exception as exc:
                logger.warning("No se pudo leer metadatos de cuarentena: %s", exc)

        # ── Mover el archivo al destino ───────────────────────────────
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(quarantine_path), str(destination))
        except Exception as exc:
            logger.error("Error restaurando %s a %s: %s", quarantine_path, destination, exc)
            return RestoreResult(
                success=False,
                destination=None,
                integrity_ok=False,
                error=f"RESTORE_ERROR: {exc}",
            )

        # ── Verificar integridad SHA-256 ──────────────────────────────
        integrity_ok = False
        if expected_sha256:
            try:
                actual_sha256 = _compute_sha256(destination)
                integrity_ok = actual_sha256 == expected_sha256
                if not integrity_ok:
                    logger.warning(
                        "Integridad SHA-256 fallida al restaurar %s: "
                        "esperado=%s actual=%s",
                        destination.name,
                        expected_sha256,
                        actual_sha256,
                    )
            except Exception as exc:
                logger.warning("No se pudo verificar SHA-256 de restauración: %s", exc)
        else:
            # Sin metadatos, no podemos verificar
            integrity_ok = False

        logger.info(
            "Archivo restaurado: dest=%s | integrity_ok=%s",
            destination,
            integrity_ok,
        )

        return RestoreResult(
            success=True,
            destination=destination,
            integrity_ok=integrity_ok,
            error=None,
        )

    def list_quarantined(self) -> List[Dict[str, Any]]:
        """
        Lista todos los archivos en cuarentena con sus metadatos.

        Returns:
            Lista de dicts con la metadata de cada archivo cuarentenado.
        """
        results: List[Dict[str, Any]] = []

        if not self.quarantine_dir.exists():
            return results

        for meta_file in self.quarantine_dir.glob("*.meta.json"):
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                # Verificar que el archivo .quar asociado exista
                quar_name = meta_file.stem  # e.g. abc12345_20240101T000000
                quar_path = self.quarantine_dir / f"{quar_name}.quar"
                meta["quar_exists"] = quar_path.exists()
                results.append(meta)
            except Exception as exc:
                logger.warning("Error leyendo metadatos %s: %s", meta_file, exc)

        return results
