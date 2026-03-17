"""
⚠️  DEPRECATED — Este archivo ha sido reemplazado por backend/app/main.py

El nuevo backend vive en backend/app/ con la arquitectura definida en el PRD:
  - backend/app/main.py           → FastAPI app + CORS + routers
  - backend/app/api/routes/       → Endpoints separados por dominio
  - backend/app/services/         → Lógica de negocio
  - backend/app/schemas/          → DTOs Pydantic
  - backend/app/integrations/     → Supabase, N8N

Para iniciar el nuevo backend:
    uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

Este archivo se mantiene temporalmente por referencia.
Se eliminará en una futura versión.
"""

import warnings
warnings.warn(
    "api_server.py está DEPRECATED. Usa 'uvicorn backend.app.main:app' en su lugar.",
    DeprecationWarning,
    stacklevel=1,
)

# Re-export para no romper scripts que importen directamente
from backend.app.main import app  # noqa: F401
