"""
backend/app/api/routes/scan.py — Endpoints de escaneo (hardened).

Defino las rutas POST /scan/file y POST /scan/multiple según el PRD.
Mantengo los endpoints delgados: solo recibo la request, delego
la lógica al scan_service y retorno la respuesta estandarizada.

Hardening (Tarea 9 — Auditoría):
  9.1 — Extensiones dobles sospechosas → HTTP 400
  9.2 — Lectura en streaming con límite MAX_UPLOAD_BYTES
  9.3 — Sanitización de caracteres de control y Unicode de dirección
  9.4 — Rate limiting por user_id (sliding window 60s)
  9.5 — Limpieza de archivos temporales antiguos (> 100 archivos)
  9.6 — Eliminación garantizada del temporal en bloque finally
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException

# Agrego la raíz del proyecto al path para importar módulos existentes
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.config import MAX_UPLOAD_BYTES, MAX_UPLOAD_MB
from backend.app.schemas.dto import ScanResult, ScanType
from backend.app.utils.response import success_response, error_response
from backend.app.services.scan_service import scan_single_file, scan_multiple_files
from backend.app.integrations.supabase_client import save_scan_safe, sync_user, fetch_recent_scans
from backend.app.api.dependencies.auth import get_current_user
from configs.settings import RATE_LIMIT_SCANS_PER_MINUTE
from utils.logger import setup_logger

logger = setup_logger("backend.routes.scan")

router = APIRouter(prefix="/scan", tags=["Escaneo"])


# ---------------------------------------------------------------------------
# 9.1 — Detección de extensiones dobles sospechosas
# ---------------------------------------------------------------------------

DOUBLE_EXT_PATTERN = re.compile(
    r'\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|zip|rar|mp3|mp4|txt|csv|ppt|pptx)'
    r'\.(exe|dll|sys|bat|ps1|vbs|cmd|scr|com|msi|pif|hta|wsf|wsh|cpl)$',
    re.IGNORECASE,
)


def _has_double_extension(filename: str) -> bool:
    """
    Detecta extensiones dobles sospechosas (ej: report.pdf.exe).

    Estas son una técnica común de ingeniería social donde el atacante
    oculta la extensión real del ejecutable detrás de una extensión benigna.
    """
    return bool(DOUBLE_EXT_PATTERN.search(filename))


# ---------------------------------------------------------------------------
# 9.3 — Sanitización de caracteres peligrosos en nombre de archivo
# ---------------------------------------------------------------------------

# Caracteres Unicode de dirección que pueden usarse para spoofear
# el nombre visible del archivo (ej: RLO U+202E invierte el texto)
_BIDI_CONTROL_CHARS = frozenset("\u202a\u202b\u202c\u202d\u202e\u200e\u200f\u2066\u2067\u2068\u2069")


def _has_control_chars(filename: str) -> bool:
    """Detecta caracteres de control ASCII y Unicode de dirección en el nombre."""
    return any(ord(c) < 0x20 or c in _BIDI_CONTROL_CHARS for c in filename)


def _sanitize_filename(filename: str | None) -> str:
    """
    Sanitizo el nombre de archivo eliminando:
    - Path traversal (../, etc.)
    - Caracteres de control ASCII (< 0x20)
    - Caracteres Unicode de dirección (RLO, LRO, etc.)
    - Caracteres peligrosos del sistema de archivos
    """
    if not filename:
        return "uploaded.bin"

    safe_name = Path(filename).name.strip()
    if not safe_name:
        return "uploaded.bin"

    # Eliminar caracteres de control y Unicode de dirección
    normalized = ""
    for ch in safe_name:
        if ord(ch) < 0x20 or ch in _BIDI_CONTROL_CHARS:
            continue  # Eliminar silenciosamente
        elif ch.isalnum() or ch in {"-", "_", "."}:
            normalized += ch
        else:
            normalized += "_"

    return (normalized[:120] or "uploaded.bin")


# ---------------------------------------------------------------------------
# 9.2 — Lectura en streaming con límite de tamaño
# ---------------------------------------------------------------------------

class FileTooLargeError(Exception):
    """El archivo excede el tamaño máximo permitido."""
    pass


async def _read_streaming(file: UploadFile, max_bytes: int) -> bytes:
    """
    Lee el archivo subido en chunks, verificando el tamaño máximo.

    En lugar de leer todo en memoria de una sola vez (lo que permitiría
    un ataque de DoS por agotamiento de RAM), leemos en chunks de 64 KB
    y verificamos el acumulado contra el límite.

    Args:
        file: Archivo subido.
        max_bytes: Tamaño máximo en bytes.

    Returns:
        Contenido completo del archivo.

    Raises:
        FileTooLargeError: Si el archivo excede max_bytes.
    """
    chunks: list[bytes] = []
    total_size = 0
    chunk_size = 64 * 1024  # 64 KB

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_bytes:
            raise FileTooLargeError(
                f"Archivo excede el límite de {max_bytes // (1024 * 1024)} MB"
            )
        chunks.append(chunk)

    return b"".join(chunks)


# ---------------------------------------------------------------------------
# 9.4 — Rate limiting por user_id con sliding window de 60s
# ---------------------------------------------------------------------------

_rate_limit_store: dict[str, deque] = defaultdict(deque)


def _check_rate_limit(user_id: str, *, max_per_minute: int) -> bool:
    """
    Verifica si el usuario ha excedido el límite de scans por minuto.

    Implementa sliding window de 60 segundos en memoria.
    Para producción a escala, reemplazar por Redis.

    Args:
        user_id: ID del usuario.
        max_per_minute: Máximo de scans permitidos por minuto.

    Returns:
        True si la request está permitida, False si excede el límite.
    """
    now = time.time()
    window = _rate_limit_store[user_id]

    # Eliminar timestamps que ya salieron de la ventana de 60s
    while window and now - window[0] > 60:
        window.popleft()

    if len(window) >= max_per_minute:
        return False

    window.append(now)
    return True


# ---------------------------------------------------------------------------
# 9.5 — Limpieza de archivos temporales antiguos
# ---------------------------------------------------------------------------

def _cleanup_old_temp_files(tmp_dir: Path, max_files: int = 100) -> None:
    """
    Limpia archivos temporales antiguos si hay más de max_files en el directorio.

    Esto previene que el directorio de uploads crezca indefinidamente si
    fallan las limpiezas individuales en el bloque finally.
    """
    try:
        if not tmp_dir.exists():
            return

        files = sorted(tmp_dir.iterdir(), key=lambda f: f.stat().st_mtime)
        if len(files) <= max_files:
            return

        # Eliminar los más viejos para dejar solo max_files
        to_remove = len(files) - max_files
        for f in files[:to_remove]:
            try:
                if f.is_file():
                    f.unlink()
                    logger.debug("Archivo temporal antiguo eliminado: %s", f.name)
            except Exception:
                pass

        logger.info(
            "Limpieza de temporales: eliminados %d archivos de %s",
            to_remove, tmp_dir,
        )
    except Exception as exc:
        logger.warning("Error en limpieza de temporales: %s", exc)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/file",
    summary="Escanear un archivo individual",
    description="Recibe un archivo, ejecuta el modelo ML y retorna la clasificación tripartita.",
    responses={
        200: {"description": "Escaneo exitoso"},
        400: {"description": "Archivo inválido, vacío o extensión doble sospechosa"},
        413: {"description": "Archivo demasiado grande"},
        429: {"description": "Demasiadas solicitudes — rate limit excedido"},
        500: {"description": "Error interno del servidor"},
    },
)
async def scan_file(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    """
    POST /scan/file — Escaneo individual de archivo (hardened).

    Flujo completo según PRD sección 4.4 con hardening de seguridad:
    1. Validar rate limit del usuario
    2. Validar nombre de archivo (control chars, double extension)
    3. Leer en streaming con límite de tamaño
    4. Guardar temporalmente en disco
    5. Ejecutar scan_single_file() (motor ML + clasificación tripartita)
    6. Guardar resultado en Supabase
    7. Retornar success_response()
    8. Limpiar archivo temporal (garantizado en finally)
    """
    # --- 9.4: Rate limiting ---
    user_id = user.get("id", "unknown")
    if not _check_rate_limit(user_id, max_per_minute=RATE_LIMIT_SCANS_PER_MINUTE):
        logger.warning(
            "Rate limit excedido para user=%s (máx %d/min)",
            user_id, RATE_LIMIT_SCANS_PER_MINUTE,
        )
        return error_response(
            f"Demasiadas solicitudes. Máximo {RATE_LIMIT_SCANS_PER_MINUTE} escaneos por minuto.",
            429,
        )

    # --- Validación de archivo ---
    if not file.filename:
        return error_response("Nombre de archivo vacío.", 400)

    # 9.3: Detectar caracteres de control antes de sanitizar
    if _has_control_chars(file.filename):
        logger.warning(
            "Nombre de archivo con caracteres de control rechazado: %r",
            file.filename[:50],
        )
        return error_response(
            "El nombre de archivo contiene caracteres no permitidos.", 400
        )

    # 9.1: Detectar extensiones dobles sospechosas ANTES de guardar en disco
    if _has_double_extension(file.filename):
        logger.warning(
            "Extensión doble sospechosa rechazada: %s", file.filename
        )
        return error_response(
            "Nombre de archivo con extensión doble sospechosa no permitido "
            "(ej: report.pdf.exe).",
            400,
        )

    safe_name = _sanitize_filename(file.filename)

    # 9.2: Lectura en streaming con límite de tamaño
    try:
        content = await _read_streaming(file, MAX_UPLOAD_BYTES)
    except FileTooLargeError:
        return error_response(
            f"Archivo demasiado grande. Máximo permitido: {MAX_UPLOAD_MB} MB.",
            413,
        )
    except Exception as exc:
        logger.error("Error leyendo archivo de upload: %s", exc)
        return error_response("Error leyendo el archivo.", 400)

    if not content:
        return error_response("El archivo está vacío.", 400)

    # --- Guardo en archivo temporal para que el motor ML lo procese ---
    tmp_dir = Path(tempfile.gettempdir()) / "shadownet_uploads"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    # 9.5: Limpiar archivos temporales antiguos si hay > 100
    _cleanup_old_temp_files(tmp_dir, max_files=100)

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

        # Inyecto datos del usuario autenticado
        scan_result.user_id = user["id"]
        scan_result.user_email = user["email"]

        # Sincronizo usuario y guardo en Supabase
        sync_user(user)
        save_scan_safe(scan_result.model_dump())

        return success_response(scan_result)

    except FileNotFoundError as exc:
        logger.error("Archivo no encontrado: %s", exc)
        return error_response(str(exc), 404)

    except Exception as exc:
        logger.error("Error durante escaneo de %s: %s", safe_name, exc)
        return error_response(f"Error interno durante el escaneo: {exc}", 500)

    finally:
        # 9.6: Eliminación GARANTIZADA del archivo temporal
        try:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


@router.post(
    "/multiple",
    summary="Escanear múltiples archivos",
    description="Recibe varios archivos, ejecuta el modelo ML en cada uno y retorna los resultados.",
    responses={
        200: {"description": "Escaneo exitoso de todos los archivos"},
        400: {"description": "Sin archivos proporcionados o extensión doble sospechosa"},
        429: {"description": "Rate limit excedido"},
        500: {"description": "Error interno del servidor"},
    },
)
async def scan_multiple(files: List[UploadFile] = File(...), user: dict = Depends(get_current_user)):
    """
    POST /scan/multiple — Escaneo de múltiples archivos (hardened).

    Proceso cada archivo secuencialmente:
    1. Validar rate limit
    2. Validar y guardar cada archivo temporalmente
    3. Ejecutar scan_multiple_files() sobre todos
    4. Guardar cada resultado en Supabase
    5. Retornar la lista de resultados
    """
    if not files:
        return error_response("No se proporcionaron archivos.", 400)

    # 9.4: Rate limiting (una verificación por batch, no por archivo)
    user_id = user.get("id", "unknown")
    if not _check_rate_limit(user_id, max_per_minute=RATE_LIMIT_SCANS_PER_MINUTE):
        return error_response(
            f"Demasiadas solicitudes. Máximo {RATE_LIMIT_SCANS_PER_MINUTE} escaneos por minuto.",
            429,
        )

    tmp_dir = Path(tempfile.gettempdir()) / "shadownet_uploads"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    # 9.5: Limpieza preventiva
    _cleanup_old_temp_files(tmp_dir, max_files=100)

    temp_files: List[tuple[Path, str]] = []

    try:
        # Guardo todos los archivos temporalmente
        for f in files:
            # 9.1: Validar extensión doble
            if f.filename and _has_double_extension(f.filename):
                logger.warning("Extensión doble rechazada en batch: %s", f.filename)
                continue

            # 9.3: Validar caracteres de control
            if f.filename and _has_control_chars(f.filename):
                logger.warning("Caracteres de control rechazados en batch: %r", f.filename[:50])
                continue

            safe_name = _sanitize_filename(f.filename)

            # 9.2: Lectura en streaming
            try:
                content = await _read_streaming(f, MAX_UPLOAD_BYTES)
            except FileTooLargeError:
                logger.warning(
                    "Archivo demasiado grande omitido (> %s MB): %s",
                    MAX_UPLOAD_MB,
                    safe_name,
                )
                continue
            except Exception:
                logger.warning("Error leyendo archivo en batch: %s", safe_name)
                continue

            if not content:
                logger.warning("Archivo vacío omitido: %s", safe_name)
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
        sync_user(user)
        for i, (_, original_name) in enumerate(temp_files):
            if i < len(results):
                results[i].file_name = original_name
                results[i].user_id = user["id"]
                results[i].user_email = user["email"]
                save_scan_safe(results[i].model_dump())

        # Convierto a lista de dicts para la respuesta
        results_data = [r.model_dump() for r in results]
        return success_response(results_data)

    except Exception as exc:
        logger.error("Error en escaneo múltiple: %s", exc)
        return error_response(f"Error interno: {exc}", 500)

    finally:
        # 9.6: Limpieza GARANTIZADA de archivos temporales
        for tmp_path, _ in temp_files:
            try:
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
            except Exception:
                pass


@router.get(
    "/recent",
    summary="Últimos escaneos del usuario",
    description="Lista los resultados guardados en Supabase para el usuario autenticado.",
)
async def scan_recent(
    user: dict = Depends(get_current_user),
    limit: int = 10,
):
    """
    GET /scan/recent — Datos reales desde Supabase (sin inventar actividad en el dashboard).

    Si Supabase no está configurado o falla, devuelvo lista vacía (status success).
    """
    lim = max(1, min(limit, 50))
    rows = fetch_recent_scans(user["id"], limit=lim)
    return success_response(rows)


@router.get(
    "/realtime",
    summary="Monitoreo de procesos en tiempo real",
    description="Lista procesos activos del sistema con métricas de CPU/memoria y nivel de riesgo.",
    responses={
        200: {"description": "Lista de procesos activos"},
        500: {"description": "Error al obtener procesos"},
    },
)
async def scan_realtime(user: dict = Depends(get_current_user)):
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
