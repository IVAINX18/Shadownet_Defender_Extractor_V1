"""
backend/app/utils/response.py — Funciones de respuesta estandarizada.

Centralizo la construcción de respuestas JSON para que todos los endpoints
retornen el mismo formato. Esto evita inconsistencias y facilita el
parseo en el frontend.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi.responses import JSONResponse


def success_response(data: Any, *, status_code: int = 200) -> JSONResponse:
    """
    Construye una respuesta exitosa con formato estándar del PRD (sección 19.6).

    Args:
        data: Contenido de la respuesta (dict, list o Pydantic model).
        status_code: Código HTTP (default 200).

    Returns:
        JSONResponse con estructura {"status": "success", "data": ...}
    """
    # Si es un modelo Pydantic, lo convierto a dict
    if hasattr(data, "model_dump"):
        data = data.model_dump()
    elif hasattr(data, "dict"):
        data = data.dict()

    return JSONResponse(
        status_code=status_code,
        content={
            "status": "success",
            "data": data,
        },
    )


def error_response(message: str, code: int) -> JSONResponse:
    """
    Construye una respuesta de error con formato estándar del PRD (sección 19.7).

    Args:
        message: Descripción del error para el frontend.
        code: Código HTTP del error.

    Returns:
        JSONResponse con estructura {"status": "error", "message": ..., "code": ...}
    """
    return JSONResponse(
        status_code=code,
        content={
            "status": "error",
            "message": message,
            "code": code,
        },
    )
