"""
backend/app/main.py — Punto de entrada de la aplicación FastAPI.

Configuro la app FastAPI con:
- CORSMiddleware para permitir comunicación desde el frontend Electron
- Registro de todos los routers (scan, analysis, health)
- Metadata de la API para documentación Swagger/OpenAPI

Este archivo es el equivalente al main.py del PRD sección 4.2,
dentro de la estructura backend/app/.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# Agrego la raíz del proyecto al PATH para que los módulos existentes
# (core, models, extractors, utils, configs) se puedan importar sin
# modificar su estructura original.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Cargo variables de entorno desde .env si existe
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    env_path = _PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv no instalado, uso env vars del sistema

# ---------------------------------------------------------------------------
# Importo los routers después de configurar el PATH
# ---------------------------------------------------------------------------
from backend.app.api.routes.scan import router as scan_router
from backend.app.api.routes.analysis import router as analysis_router
from backend.app.api.routes.health import router as health_router

# ---------------------------------------------------------------------------
# Creo la aplicación FastAPI
# ---------------------------------------------------------------------------
app = FastAPI(
    title="ShadowNet Defender API",
    description=(
        "API de ciberseguridad basada en IA para detección de malware "
        "mediante análisis estático y aprendizaje automático."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS — Configuro para permitir comunicación desde el frontend Electron
#
# En producción, el frontend Electron corre en localhost, pero uso
# origins configurables vía variable de entorno para flexibilidad.
# ---------------------------------------------------------------------------
_cors_origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173,http://localhost:8080")
_cors_origins = [origin.strip() for origin in _cors_origins_raw.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Registro de routers — Cada módulo de rutas se registra aquí
# ---------------------------------------------------------------------------
app.include_router(scan_router)
app.include_router(analysis_router)
app.include_router(health_router)


from fastapi import Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse


# ---------------------------------------------------------------------------
# Manejo global de errores — Formato estandarizado para TODAS las excepciones
# ---------------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Manejo de errores HTTP con formato estándar."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail,
            "code": exc.status_code,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Manejo de excepciones no capturadas — evita HTML por defecto de FastAPI."""
    import logging
    logging.getLogger("backend.main").error("Error no capturado: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": str(exc),
            "code": 500,
        },
    )


# ---------------------------------------------------------------------------
# Punto de entrada para ejecución directa
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))

    uvicorn.run(
        "backend.app.main:app",
        host=host,
        port=port,
        reload=True,
    )

