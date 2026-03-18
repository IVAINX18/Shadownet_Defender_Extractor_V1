"""
backend/app/api/routes/scan.py — Endpoints de escaneo.

Defino las rutas POST /scan/file y POST /scan/multiple según el PRD.
Mantengo los endpoints delgados: solo recibo la request, delego
la lógica al scan_service y retorno la respuesta estandarizada.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path
from typing import List

from fastapi import APIRouter, File, UploadFile, HTTPException

# Agrego la raíz del proyecto al path para importar módulos existentes
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.schemas.dto import ScanResult, ScanType
from backend.app.utils.response import success_response, error_response
from backend.app.services.scan_service import scan_single_file, scan_multiple_files
from backend.app.integrations.supabase_client import save_scan_safe
from utils.logger import setup_logger

logger = setup_logger("backend.routes.scan")

router = APIRouter(prefix="/scan", tags=["Escaneo"])

# Tamaño máximo de archivo permitido (20 MB)
MAX_UPLOAD_BYTES = 20 * 1024 * 1024


def _sanitize_filename(filename: str | None) -> str:
    """
    Sanitizo el nombre de archivo para evitar path traversal y caracteres peligrosos.
    """
    if not filename:
        return "uploaded.bin"
    safe_name = Path(filename).name.strip()
    if not safe_name:
        return "uploaded.bin"
    normalized = "".join(
        ch if (ch.isalnum() or ch in {"-", "_", "."}) else "_"
        for ch in safe_name
    )
    return normalized[:120] or "uploaded.bin"


@router.post(
    "/file",
    summary="Escanear un archivo individual",
    description="Recibe un archivo, ejecuta el modelo ML y retorna la clasificación tripartita.",
    responses={
        200: {"description": "Escaneo exitoso"},
        400: {"description": "Archivo inválido o vacío"},
        413: {"description": "Archivo demasiado grande"},
        500: {"description": "Error interno del servidor"},
    },
)
async def scan_file(file: UploadFile = File(...)):
    """
    POST /scan/file — Escaneo individual de archivo.

    Flujo completo según PRD sección 4.4:
    1. Recibo el archivo vía UploadFile
    2. Valido tamaño y nombre
    3. Guardo temporalmente en disco
    4. Ejecuto scan_single_file() (motor ML + clasificación tripartita)
    5. Guardo resultado en Supabase
    6. Retorno success_response()
    """
    # --- Validación de archivo ---
    if not file.filename:
        return error_response("Nombre de archivo vacío.", 400)

    safe_name = _sanitize_filename(file.filename)

    # Leo el contenido del archivo
    try:
        content = await file.read()
    except Exception as exc:
        logger.error("Error leyendo archivo de upload: %s", exc)
        return error_response("Error leyendo el archivo.", 400)

    if not content:
        return error_response("El archivo está vacío.", 400)

    if len(content) > MAX_UPLOAD_BYTES:
        return error_response(
            f"Archivo demasiado grande. Máximo permitido: {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
            413,
        )

    # --- Guardo en archivo temporal para que el motor ML lo procese ---
    tmp_dir = Path(tempfile.gettempdir()) / "shadownet_uploads"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = tmp_dir / f"{int(time.time() * 1000)}-{safe_name}"

    try:
        tmp_path.write_bytes(content)

        # Ejecuto el escaneo con clasificación tripartita
        scan_result: ScanResult = scan_single_file(
            tmp_path,
            scan_type=ScanType.SINGLE,
        )

        # Actualizo el nombre al original (no al temporal)
        scan_result.file_name = safe_name

        # Guardo en Supabase sin bloquear el flujo
        save_scan_safe(scan_result.model_dump())

        return success_response(scan_result)

    except FileNotFoundError as exc:
        logger.error("Archivo no encontrado: %s", exc)
        return error_response(str(exc), 404)

    except Exception as exc:
        logger.error("Error durante escaneo de %s: %s", safe_name, exc)
        return error_response(f"Error interno durante el escaneo: {exc}", 500)

    finally:
        # Limpio el archivo temporal
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


@router.post(
    "/multiple",
    summary="Escanear múltiples archivos",
    description="Recibe varios archivos, ejecuta el modelo ML en cada uno y retorna los resultados.",
    responses={
        200: {"description": "Escaneo exitoso de todos los archivos"},
        400: {"description": "Sin archivos proporcionados"},
        500: {"description": "Error interno del servidor"},
    },
)
async def scan_multiple(files: List[UploadFile] = File(...)):
    """
    POST /scan/multiple — Escaneo de múltiples archivos.

    Proceso cada archivo secuencialmente:
    1. Valido y guardo cada archivo temporalmente
    2. Ejecuto scan_multiple_files() sobre todos
    3. Guardo cada resultado en Supabase
    4. Retorno la lista de resultados
    """
    if not files:
        return error_response("No se proporcionaron archivos.", 400)

    tmp_dir = Path(tempfile.gettempdir()) / "shadownet_uploads"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    temp_files: List[tuple[Path, str]] = []

    try:
        # Guardo todos los archivos temporalmente
        for f in files:
            safe_name = _sanitize_filename(f.filename)
            content = await f.read()

            if not content:
                logger.warning("Archivo vacío omitido: %s", safe_name)
                continue

            if len(content) > MAX_UPLOAD_BYTES:
                logger.warning("Archivo demasiado grande omitido: %s", safe_name)
                continue

            tmp_path = tmp_dir / f"{int(time.time() * 1000)}-{safe_name}"
            tmp_path.write_bytes(content)
            temp_files.append((tmp_path, safe_name))

        if not temp_files:
            return error_response(
                "Ningún archivo válido para escanear.", 400
            )

        # Ejecuto el escaneo de todos los archivos
        file_paths = [fp for fp, _ in temp_files]
        results = scan_multiple_files(file_paths)

        # Corrijo los nombres de archivo al original y guardo en Supabase
        for i, (_, original_name) in enumerate(temp_files):
            if i < len(results):
                results[i].file_name = original_name
                save_scan_safe(results[i].model_dump())

        # Convierto a lista de dicts para la respuesta
        results_data = [r.model_dump() for r in results]
        return success_response(results_data)

    except Exception as exc:
        logger.error("Error en escaneo múltiple: %s", exc)
        return error_response(f"Error interno: {exc}", 500)

    finally:
        # Limpio archivos temporales
        for tmp_path, _ in temp_files:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass


@router.get(
    "/realtime",
    summary="Monitoreo de procesos en tiempo real",
    description="Lista procesos activos del sistema con métricas de CPU/memoria y nivel de riesgo.",
    responses={
        200: {"description": "Lista de procesos activos"},
        500: {"description": "Error al obtener procesos"},
    },
)
async def scan_realtime():
    """
    GET /scan/realtime — Monitoreo en tiempo real con psutil.

    Delego la lógica al realtime_service para mantener el endpoint delgado.
    """
    try:
        from backend.app.services.realtime_service import get_processes
        processes = get_processes()
        return success_response(processes)
    except ImportError as exc:
        logger.error("psutil no disponible: %s", exc)
        return error_response(str(exc), 500)
    except Exception as exc:
        logger.error("Error en monitoreo realtime: %s", exc)
        return error_response(f"Error obteniendo procesos: {exc}", 500)

