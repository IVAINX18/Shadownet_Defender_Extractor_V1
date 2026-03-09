#!/usr/bin/env python
"""
Script de inicio local para ShadowNet Defender API.

El servidor corre completamente en local.
Se comunica con flujos de n8n expuestos mediante un túnel ngrok.
No requiere Render ni Cloudflare.
"""
from dotenv import load_dotenv
import os

# Cargar variables desde .env.test (URLs ngrok de n8n configuradas aquí)
load_dotenv('.env.test')

# Asegurar que las variables estén disponibles en os.environ para el servidor
for key in ['N8N_ENABLED', 'ENVIRONMENT', 'N8N_WEBHOOK_TEST', 'N8N_WEBHOOK_PROD', 'N8N_TIMEOUT_SECONDS']:
    value = os.getenv(key)
    if value:
        os.environ[key] = value
        print(f"{key}={value}")

# Iniciar servidor local — escucha en todas las interfaces en el puerto 8000
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )
