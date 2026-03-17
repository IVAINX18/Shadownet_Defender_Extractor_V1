"""
⚠️  DEPRECATED — Este archivo ha sido reemplazado por backend/app/main.py

Para iniciar el nuevo backend:
    uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

Este archivo se mantiene temporalmente por referencia.
Se eliminará en una futura versión.
"""

import warnings
warnings.warn(
    "start_server.py está DEPRECATED. Usa 'uvicorn backend.app.main:app' en su lugar.",
    DeprecationWarning,
    stacklevel=1,
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
