"""
core/unpacking/upx_detector.py — Módulo de detección y desempacado UPX.

Los empacadores como UPX comprimen el código ejecutable real del malware,
ocultando sus strings, importaciones y secciones del análisis estático.
Este módulo detecta la presencia de UPX y desempaca el archivo en memoria
antes de que el extractor de features lo procese.

¿Por qué existe este módulo?
    Cuando un troyano o gusano está empacado con UPX, el extractor de
    features analiza el DESCOMPRESOR de UPX, no el malware real. El
    descompresor es un programa pequeño y "benigno" que el modelo nunca
    ha visto como malware, por lo que lo clasifica como BENIGN incluso
    si el contenido real es un virus.

    Al desempacar ANTES de extraer features, le damos al modelo ONNX
    el ejecutable real para analizar.
"""
from __future__ import annotations

import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional

import pefile

from utils.logger import setup_logger

logger = setup_logger(__name__)

# Nombres de sección que UPX usa por defecto
_UPX_SECTION_NAMES = {"UPX0", "UPX1", "UPX2"}

# Tiempo máximo de espera para el proceso de desempacado (segundos)
_UNPACK_TIMEOUT_SEC = 15


class UPXUnpacker:
    """
    Detecta si un archivo PE está empacado con UPX y lo desempaca.

    Uso típico:
        unpacker = UPXUnpacker()
        result = unpacker.try_unpack(Path("/tmp/malware.exe"))
        if result.was_unpacked:
            # Analizar result.unpacked_path en lugar del original
            features = extractor.extract(result.unpacked_path)
            result.cleanup()  # Limpiar archivo temporal
        else:
            features = extractor.extract(original_path)
    """

    def __init__(self) -> None:
        self._upx_available = self._check_upx_binary()

    # ------------------------------------------------------------------
    # API Pública
    # ------------------------------------------------------------------

    def is_packed(self, raw_data: bytes) -> bool:
        """
        Determina si los bytes de un PE contienen firmas de UPX.

        Estrategia de detección en dos capas:
        1. Nombres de sección: UPX renombra las secciones a UPX0/UPX1/UPX2.
        2. Firma de bytes: Busca la string 'UPX!' en los primeros 2 KB del
           archivo, que es la firma que UPX añade al header del archivo.
        """
        # Capa 1: Firma literal en el header (más rápida)
        if b"UPX!" in raw_data[:2048]:
            logger.debug("Firma UPX! encontrada en el header del archivo.")
            return True

        # Capa 2: Nombres de secciones del PE
        try:
            pe = pefile.PE(data=raw_data, fast_load=True)
            section_names = {
                s.Name.decode("utf-8", errors="ignore").strip("\x00").upper()
                for s in pe.sections
            }
            pe.close()
            if section_names & _UPX_SECTION_NAMES:
                logger.debug("Secciones UPX detectadas: %s", section_names & _UPX_SECTION_NAMES)
                return True
        except Exception:
            pass

        return False

    def try_unpack(self, file_path: Path) -> "UnpackResult":
        """
        Intenta desempacar el archivo si está empacado con UPX.

        Retorna siempre un UnpackResult, que indica si se desempacó
        exitosamente y proporciona la ruta al archivo resultante.
        Si no se desempacó (por cualquier razón), result.unpacked_path
        apunta al archivo original para que el flujo continúe sin cambios.
        """
        # Leer los bytes del archivo una sola vez
        try:
            raw_data = file_path.read_bytes()
        except Exception as exc:
            logger.error("No se pudo leer el archivo %s: %s", file_path, exc)
            return UnpackResult(was_unpacked=False, unpacked_path=file_path)

        # Verificar si está empacado
        if not self.is_packed(raw_data):
            return UnpackResult(was_unpacked=False, unpacked_path=file_path)

        logger.info("Archivo empacado con UPX detectado: %s", file_path.name)

        # Sin el binario upx disponible, no podemos desempacar
        if not self._upx_available:
            logger.warning(
                "Binario 'upx' no encontrado en PATH. Instalarlo con: "
                "sudo apt install upx-ucl  |  brew install upx"
            )
            return UnpackResult(was_unpacked=False, unpacked_path=file_path)

        return self._run_upx_decompress(file_path)

    # ------------------------------------------------------------------
    # Implementación Privada
    # ------------------------------------------------------------------

    @staticmethod
    def _check_upx_binary() -> bool:
        """Verifica si el binario upx está disponible en el PATH del sistema."""
        available = shutil.which("upx") is not None
        if available:
            logger.debug("Binario UPX encontrado en PATH.")
        else:
            logger.info(
                "Binario UPX no encontrado. El desempacado estará deshabilitado. "
                "Para habilitarlo: sudo apt install upx-ucl"
            )
        return available

    def _run_upx_decompress(self, file_path: Path) -> "UnpackResult":
        """
        Ejecuta 'upx -d' para descomprimir el archivo en un directorio temporal.

        El archivo original NO se modifica. El resultado se escribe en /tmp/
        con un nombre único basado en el timestamp para evitar colisiones.
        """
        tmp_dir = Path(tempfile.mkdtemp(prefix="shadownet_unpack_"))
        unpacked_path = tmp_dir / f"unpacked_{file_path.name}"

        try:
            proc = subprocess.run(
                ["upx", "--decompress", "--force", f"--output={unpacked_path}", str(file_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=_UNPACK_TIMEOUT_SEC,
            )

            if proc.returncode == 0 and unpacked_path.exists() and unpacked_path.stat().st_size > 0:
                logger.info(
                    "Desempacado UPX exitoso: %s → %s (%.1f KB → %.1f KB)",
                    file_path.name,
                    unpacked_path.name,
                    file_path.stat().st_size / 1024,
                    unpacked_path.stat().st_size / 1024,
                )
                return UnpackResult(was_unpacked=True, unpacked_path=unpacked_path, _tmp_dir=tmp_dir)
            else:
                logger.warning(
                    "UPX descompresión falló para %s (rc=%d): %s",
                    file_path.name,
                    proc.returncode,
                    proc.stderr.strip(),
                )
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return UnpackResult(was_unpacked=False, unpacked_path=file_path)

        except subprocess.TimeoutExpired:
            logger.error("Timeout (%ds) desempacando %s.", _UNPACK_TIMEOUT_SEC, file_path.name)
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return UnpackResult(was_unpacked=False, unpacked_path=file_path)
        except Exception as exc:
            logger.error("Error inesperado al desempacar %s: %s", file_path.name, exc)
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return UnpackResult(was_unpacked=False, unpacked_path=file_path)


class UnpackResult:
    """
    Contenedor del resultado de un intento de desempacado.

    Attributes:
        was_unpacked: True si el archivo fue desempacado exitosamente.
        unpacked_path: Ruta al archivo a analizar (desempacado u original).
    """

    def __init__(self, *, was_unpacked: bool, unpacked_path: Path, _tmp_dir: Optional[Path] = None):
        self.was_unpacked = was_unpacked
        self.unpacked_path = unpacked_path
        self._tmp_dir = _tmp_dir

    def cleanup(self) -> None:
        """
        Elimina el directorio temporal creado durante el desempacado.
        Llamar siempre después de terminar el análisis del archivo desempacado.
        """
        if self._tmp_dir and self._tmp_dir.exists():
            try:
                shutil.rmtree(self._tmp_dir)
                logger.debug("Directorio temporal eliminado: %s", self._tmp_dir)
            except Exception as exc:
                logger.warning("No se pudo limpiar %s: %s", self._tmp_dir, exc)
