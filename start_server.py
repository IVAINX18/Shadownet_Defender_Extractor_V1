#!/usr/bin/env python
"""Script de inicio que carga variables de entorno desde .env.test"""
from dotenv import load_dotenv
import os

# Cargar variables desde .env.test
load_dotenv('.env.test')

# Asegurar que las variables estén disponibles en os.environ para el servidor
for key in ['N8N_ENABLED', 'ENVIRONMENT', 'N8N_WEBHOOK_TEST', 'N8N_WEBHOOK_PROD', 'N8N_TIMEOUT_SECONDS']:
    value = os.getenv(key)
    if value:
        os.environ[key] = value
        print(f"{key}={value}")

# Importar y ejecutar uvicorn
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "api_server:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )
