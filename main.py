from __future__ import annotations

"""
main.py — Punto de entrada para FastAPI.

Se expone la instancia `app` definida en `api_server.py` para que el servidor
se pueda arrancar con:

    uvicorn main:app --host 0.0.0.0 --port 8000
"""

from api_server import app  # noqa: F401

