# 🧪 Test Flow — Verificación End-to-End de ShadowNet Defender

## Diagrama del flujo completo

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐    ┌──────────────┐
│  Tu PC local│    │  Cloudflare  │    │  Render (nube)  │    │  n8n Cloud   │
│             │    │  Tunnel      │    │                 │    │              │
│ Ollama:11434│◀───│*.trycloudflare│◀───│ FastAPI /scan   │───▶│ Webhook      │
│             │    │  .com        │    │ /llm/explain    │    │ → Email      │
│             │    │              │    │                 │    │ → G.Drive    │
└─────────────┘    └──────────────┘    └─────────────────┘    └──────────────┘
```

---

## Prerrequisitos

| Componente        | Estado esperado                            | Cómo verificar                          |
| ----------------- | ------------------------------------------ | --------------------------------------- |
| Ollama            | Corriendo en localhost:11434               | `curl http://localhost:11434/v1/models` |
| Modelo descargado | llama3.2:3b (o el configurado)             | `ollama list`                           |
| Cloudflare Tunnel | Activo, mostrando URL pública              | Ver terminal de cloudflared             |
| Render            | Desplegado con OLLAMA_BASE_URL actualizada | Dashboard de Render → Environment       |
| n8n               | Workflow activo con webhook                | Dashboard de n8n                        |

---

## Paso 1: Verificar Ollama local

```bash
# ¿Ollama está corriendo?
ollama ps
# o
curl http://localhost:11434/v1/models

# Respuesta esperada:
# {"object":"list","data":[{"id":"llama3.2:3b","object":"model",...}]}
```

Si no está corriendo:

```bash
./fix-ollama.sh
```

---

## Paso 2: Verificar Cloudflare Tunnel

```bash
# En otra terminal:
cloudflared tunnel --url http://localhost:11434 --http-host-header="localhost:11434"

# Busca en la salida:
# https://random-string.trycloudflare.com
```

Verificar desde otra máquina o navegador:

```bash
curl https://random-string.trycloudflare.com/v1/models
```

---

## Paso 3: Verificar que Render puede alcanzar Ollama

```bash
# Desde el dashboard de Render, verifica:
# OLLAMA_BASE_URL = https://random-string.trycloudflare.com/v1
# OLLAMA_MODEL = llama3.2:3b

# Health check del API:
curl https://shadownet-defender-extractor-v2.onrender.com/health
# Respuesta esperada: {"status":"ok","model":"loaded"}
```

---

## Paso 4: Test del endpoint /scan

```bash
curl "https://shadownet-defender-extractor-v2.onrender.com/scan?file_path=samples/procexp64.exe"
```

Respuesta esperada:

```json
{
  "file": "samples/procexp64.exe",
  "status": "detected",
  "score": 0.85,
  "label": "MALWARE",
  "confidence": "High",
  "scan_time_ms": 150.0,
  "details": { ... }
}
```

---

## Paso 5: Test del endpoint /llm/explain (Ollama vía Cloudflare Tunnel)

```bash
curl -X POST "https://shadownet-defender-extractor-v2.onrender.com/llm/explain" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "ollama",
    "model": "llama3.2:3b",
    "scan_result": {
      "file": "samples/procexp64.exe",
      "status": "detected",
      "score": 0.91,
      "label": "MALWARE",
      "confidence": "High",
      "details": {
        "entropy": 6.8,
        "suspicious_imports": ["VirtualAlloc", "WriteProcessMemory"],
        "suspicious_sections": [".rsrc"],
        "top_features": [
          {"name": "byte_entropy_mean", "value": 6.8, "impact": 0.15}
        ]
      }
    }
  }'
```

Respuesta esperada:

```json
{
  "ok": true,
  "scan_result": { ... },
  "llm": {
    "provider": "ollama",
    "model": "llama3.2:3b",
    "response_text": "{\"resumen_ejecutivo\":\"...\",\"explicacion_tecnica\":\"...\"}",
    "prompt_version": "v1"
  }
}
```

**Verificaciones clave:**

- ✅ `llm.provider` = `"ollama"` (no otro motor)
- ✅ `llm.model` = `"llama3.2:3b"` (el modelo configurado)
- ✅ `llm.response_text` contiene JSON válido con la explicación
- ✅ En la terminal de cloudflared, deberías ver requests entrantes

---

## Paso 6: Verificar n8n webhook

Después de llamar a `/scan`, verifica en n8n:

1. Abre el dashboard de n8n: https://ivainx21.app.n8n.cloud
2. Ve al workflow de ShadowNet
3. Verifica que el webhook recibió el payload
4. Verifica que el email fue enviado
5. Verifica que el reporte se guardó en Google Drive

```bash
# Test manual del webhook:
curl -X POST "https://shadownet-defender-extractor-v2.onrender.com/automation/test"
```

---

## Paso 7: Test local completo (sin Render)

Para probar todo localmente sin Render:

```bash
# Terminal 1: Ollama
ollama serve

# Terminal 2: FastAPI local
export OLLAMA_BASE_URL="http://localhost:11434/v1"
export OLLAMA_MODEL="llama3.2:3b"
python -m uvicorn api_server:app --host 127.0.0.1 --port 8000

# Terminal 3: Tests
curl http://localhost:8000/health
curl "http://localhost:8000/scan?file_path=samples/procexp64.exe"
curl -X POST "http://localhost:8000/llm/explain" \
  -H "Content-Type: application/json" \
  -d '{"file_path": "samples/procexp64.exe"}'
```

---

## Paso 8: Tests unitarios

```bash
# Ejecutar todos los tests (no requieren Ollama corriendo)
python -m pytest tests/ -v

# Solo tests del cliente Ollama
python -m pytest tests/test_ollama_client.py -v

# Solo tests de integración CLI + LLM
python -m pytest tests/test_cli_llm_integration.py -v
```

---

## Checklist de verificación final

| #   | Verificación                                      | ✅/❌ |
| --- | ------------------------------------------------- | ----- |
| 1   | Ollama corriendo localmente                       |       |
| 2   | Modelo descargado (`ollama list`)                 |       |
| 3   | Cloudflare Tunnel activo (URL pública visible)    |       |
| 4   | URL pública responde (`curl .../v1/models`)       |       |
| 5   | OLLAMA_BASE_URL configurada en Render             |       |
| 6   | `/health` responde OK                             |       |
| 7   | `/scan` retorna resultado ML                      |       |
| 8   | `/llm/explain` retorna explicación de Ollama      |       |
| 9   | n8n webhook recibe payload                        |       |
| 10  | Email enviado por n8n                             |       |
| 11  | Reporte guardado en Google Drive                  |       |
| 12  | Modelo en respuesta LLM coincide con OLLAMA_MODEL |       |
| 13  | Tests unitarios pasan (`pytest tests/ -v`)        |       |

---

## Troubleshooting

### `/llm/explain` retorna error de conexión

```
"error": "No se pudo conectar a Ollama en https://xxxx.trycloudflare.com/v1"
```

**Causa:** El Cloudflare Tunnel se cerró o la URL cambió.
**Solución:** Reinicia cloudflared y actualiza OLLAMA_BASE_URL en Render.

### `/llm/explain` retorna timeout

```
"error": "Ollama no respondió en 120 segundos"
```

**Causa:** El modelo es muy grande o es la primera carga.
**Solución:** Espera a que Ollama cargue el modelo, o usa uno más ligero (`phi3:mini`).

### n8n no recibe el webhook

**Causa:** El workflow no está activo o el webhook URL cambió.
**Solución:** Activa el workflow en n8n y verifica las URLs en las variables de entorno.

### Cloudflared muestra "Bad Request"

**Causa:** Falta `--http-host-header="localhost:11434"`.
**Solución:** Reinicia cloudflared con el flag correcto.
