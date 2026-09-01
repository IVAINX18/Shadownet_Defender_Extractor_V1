# ShadowNet Defender — Análisis de Brechas del Backend

> **Fecha:** 2026-03-17  
> **Fuentes:** [PRD.md](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/docs/PRD.md) + código actual del repositorio  
> **Alcance:** Solo backend — frontend excluido

---

## 1. Componentes Backend Identificados en el PRD

El PRD (secciones 4, 5, 6, 7, 8, 10, 11, 12) define los siguientes módulos y responsabilidades:

### 1.1 Estructura de Directorios Requerida

```
backend/app/
├── main.py
├── api/routes/ + controllers/ + dependencies/
├── services/  (scan_service, analysis_service, llm_service, realtime_service)
├── models/ml_model.py
├── schemas/dto.py
├── utils/    (file_utils, logger, security)
├── integrations/ (supabase_client, n8n_client, ollama_client)
└── config/settings.py
```

### 1.2 Endpoints Requeridos

| Método | Ruta                  | Responsabilidad                       |
|--------|-----------------------|---------------------------------------|
| `POST` | `/scan/file`          | Escaneo individual: validar → extraer features → ejecutar ML |
| `POST` | `/scan/multiple`      | Escaneo de múltiples archivos         |
| `GET`  | `/scan/realtime`      | Monitoreo de procesos activos (detección comportamiento anómalo) |
| `POST` | `/analysis/explain`   | Generar explicación con Ollama (LLM)  |
| `GET`  | `/health`             | Estado del backend                    |

### 1.3 Integraciones Requeridas

| Integración | Responsabilidad |
|-------------|----------------|
| **Supabase** | Persistir: `usuario_id`, `nombre_archivo`, `resultado`, `confianza`, `explicacion`, `fecha`, `tiempo_escaneo` |
| **N8N** | Webhook cuando `result == "malicious"` → correo Gmail + registro Google Drive |
| **Ollama** | LLM local para explicación técnica de resultados ML |

### 1.4 Modelo ML

- Formato: **ONNX** (exportado desde PyTorch)
- Llamado desde `scan_service`, desacoplado de endpoints
- Inferencia < 2 segundos
- Carga eficiente en memoria

### 1.5 Flujo Interno Completo

```
Recepción → Validación → Extracción features → Inferencia ML → Clasificación
→ Explicación LLM → Persistencia Supabase → Activación N8N (si malicioso)
```

### 1.6 Salida Estructurada Requerida

```json
{
  "file_name": "string", "scan_type": "single|multiple|realtime",
  "result": "benign|suspicious|malicious", "confidence": 0.92,
  "scan_time": "1.34s", "features_detected": [],
  "timestamp": "ISO8601", "explanation": "string",
  "risk_level": "low|medium|high"
}
```

### 1.7 Modo Offline

- Modelo local sin LLM, sin Supabase, sin N8N
- Marcar `"mode": "offline"`
- Sincronización posterior al reconectar

### 1.8 Seguridad

- Validación de archivos, sanitización de inputs
- No ejecución de archivos, variables de entorno, CORS

### 1.9 Estándares de Código

- PEP8, type hints, código modular, docstrings, comentarios explicativos

---

## 2. Estado Actual del Backend

### 2.1 ✅ Implementado Correctamente

| Componente | Archivo(s) | Notas |
|-----------|-----------|-------|
| Modelo ONNX + Scaler | [inference.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/models/inference.py) | Carga ONNX + scaler joblib, inferencia robusta con manejo de shapes |
| Extracción de features (PE) | `extractors/*.py` (11 archivos) | Extractores modularizados completos: header, imports, exports, entropy, secciones, strings |
| Motor de escaneo (Facade) | [engine.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/engine.py) | Patrón Facade, orquesta extract → predict → label. Bien documentado para juniors |
| Cliente Ollama (OpenAI SDK) | [ollama_client.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/llm/ollama_client.py) | Cliente robusto con manejo de errores diferenciado (timeout, conexión, HTTP) |
| Prompt Builder | [prompt_builder.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/llm/prompt_builder.py) | Prompt estructurado, seguro (no envía archivos), pide JSON |
| Servicio de Explicación | [explanation_service.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/llm/explanation_service.py) | Capa limpia con Protocol para LLM clients, parseo de JSON robusto |
| Cliente N8N | [n8n_client.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/integrations/n8n_client.py) | Completo: payload normalizado, telemetría, filtros por entorno/riesgo, config vía env vars |
| Pipeline Scan+Explain+N8N | [scan_pipeline.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/scan_pipeline.py) | Orquestación centralizada reutilizada por CLI y API |
| Logger con rotación | [logger.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/utils/logger.py) | Rich console + RotatingFileHandler (5MB, 3 backups) |
| Verificador de artefactos | [artifact_verifier.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/security/artifact_verifier.py) | Verificación SHA256 + tamaño contra manifest |
| Telemetría local | [telemetry_client.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/telemetry_client.py) | JSONL writer para métricas operativas |
| Tests unitarios | `tests/` (6 archivos) | Cubren extractors, ollama, n8n, LLM prompt, explanation service |

### 2.2 ⚠️ Implementado Parcialmente

| Componente | Estado | Problema |
|-----------|--------|----------|
| **API FastAPI** | Existe en [api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py) (442 líneas, archivo único monolítico) | No sigue la estructura del PRD (`api/routes/`, `controllers/`, `dependencies/`). Todo está en un solo archivo |
| **Endpoint escaneo individual** | Existe como `GET /scan-file` | PRD requiere `POST /scan/file`. Ruta y método HTTP incorrectos |
| **Endpoint escaneo múltiple** | Existe como `POST /scan-batch` | PRD requiere `POST /scan/multiple`. Ruta incorrecta |
| **Endpoint explicación LLM** | Existe como `POST /llm/explain` | PRD requiere `POST /analysis/explain`. Ruta incorrecta |
| **Endpoint health** | Existe como `GET /health` ✅ | Correcto, pero no reporta estado de servicios externos (Supabase, Ollama) |
| **Validación de archivos** | Parcial: path allowlisting + tamaño de upload | Falta validación de tipo de archivo antes del procesamiento, sanitización de nombres incompleta |
| **Configuración** | Existe en [settings.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/configs/settings.py) (22 líneas) | Solo tiene paths y thresholds. Falta: Supabase config, CORS, variables de entorno completas |
| **Clasificación tripartita** | Solo `MALWARE`/`BENIGN` | PRD requiere tres niveles: `benign`/`suspicious`/`malicious` |
| **Formato de respuesta** | Retorna schema propio | No cumple el formato de salida definido en PRD sección 19 |

### 2.3 ❌ No Implementado

| Componente del PRD | Estado |
|--------------------|--------|
| **Estructura `backend/app/`** | ❌ No existe. Todo vive en la raíz del proyecto |
| **Capa `api/routes/`** | ❌ Todos los endpoints están en [api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py) |
| **Capa `api/controllers/`** | ❌ No existe |
| **Capa `api/dependencies/`** | ❌ No existe |
| **`services/scan_service.py`** | ❌ No existe como archivo separado (lógica en [engine.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/engine.py) y [api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py)) |
| **`services/analysis_service.py`** | ❌ No existe |
| **`services/realtime_service.py`** | ❌ No existe |
| **`schemas/dto.py`** | ❌ No hay Pydantic models/DTOs definidos |
| **`utils/file_utils.py`** | ❌ No existe (sanitización embebida en [api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py)) |
| **`utils/security.py`** | ❌ No existe (hay [security/artifact_verifier.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/security/artifact_verifier.py) pero no cubre validación de inputs) |
| **`integrations/supabase_client.py`** | ❌ **NO EXISTE** — Cero integración con Supabase |
| **`GET /scan/realtime`** | ❌ No existe — Monitoreo de procesos no implementado |
| **Persistencia en Supabase** | ❌ Ningún dato se persiste en base de datos |
| **Modo Offline** | ❌ No hay detección online/offline ni sincronización posterior |
| **CORS** | ❌ No configurado — Frontend no podrá comunicarse |
| **Campo `scan_type`** | ❌ No existe en la respuesta |
| **Campo [risk_level](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/integrations/n8n_client.py#73-82)** | ❌ No existe en respuesta al frontend (solo en payload N8N) |
| **Campo `features_detected`** | ❌ No se retorna al frontend |
| **Campo `explanation`** en respuesta unificada | ❌ Se retorna en paso separado |
| **Clasificación `suspicious`** | ❌ Solo hay `MALWARE`/`BENIGN` |
| **Webhook condicional (solo `malicious`)** | ❌ N8N se dispara siempre, sin condición de `result == "malicious"` |

---

## 3. Brechas (Gap Analysis)

### 3.1 Arquitectura y Estructura

| PRD Requiere | Estado Actual | Brecha |
|-------------|--------------|--------|
| `backend/app/` con separación en capas | Archivos sueltos en raíz del proyecto | **Restructuración completa necesaria** |
| Routes → Controllers → Services | Todo en [api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py) (442 líneas) | Falta separar en 3 capas |
| Schemas/DTOs con Pydantic | Uso de `Dict` sin tipado | No hay validación de request/response |

### 3.2 Endpoints

| PRD | Actual | Brecha |
|-----|--------|--------|
| `POST /scan/file` | `GET /scan-file` | Método y ruta incorrectos |
| `POST /scan/multiple` | `POST /scan-batch` | Ruta incorrecta |
| `POST /analysis/explain` | `POST /llm/explain` | Ruta incorrecta |
| `GET /scan/realtime` | No existe | **Funcionalidad completa faltante** |
| `GET /health` | `GET /health` ✅ | Solo falta ampliar info de servicios |

### 3.3 Integraciones

| Integración | Brecha |
|------------|--------|
| **Supabase** | **100% faltante** — No hay cliente, no hay persistencia, no hay tabla definida |
| **N8N** | Integración existe pero envía siempre; PRD dice enviar solo cuando `result == "malicious"` |
| **Ollama** | Funcional ✅ — Solo la ruta del endpoint es diferente |

### 3.4 Formato de Respuesta

El PRD define una estructura clara (sección 19). La respuesta actual difiere significativamente:

```diff
- {"file": "...", "status": "detected", "score": 0.95, "label": "MALWARE", "confidence": "High"}
+ {"file_name": "...", "result": "malicious", "confidence": 0.92, "risk_level": "high",
+  "scan_type": "single", "features_detected": [...], "explanation": "...", "scan_time": "1.34s"}
```

### 3.5 Modo Offline

- No hay detección de conectividad
- No hay flag `"mode": "offline"` en respuestas
- No hay cola de sincronización para envío posterior a Supabase/N8N

---

## 4. Problemas Detectados

### 4.1 Errores de Arquitectura

> [!CAUTION]
> **API monolítica en un solo archivo** — [api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py) (442 líneas) contiene endpoints, helpers, validación, lógica de negocio y dispatch de N8N. Viola completamente la separación en capas definida en el PRD.

- **Sin capa de DTOs/Schemas**: Los endpoints reciben `Dict` genéricos sin validación Pydantic. Esto permite payloads malformados y dificulta la documentación auto-generada de FastAPI (Swagger)
- **Sin inyección de dependencias**: `engine`, [telemetry](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py#71-80), `n8n_client` se instancian como globales al inicio. No hay uso de `Depends()` de FastAPI
- **Módulos en ubicación incorrecta**: [llm_agent_bridge.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/llm_agent_bridge.py), [telemetry_client.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/telemetry_client.py), [api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py) están en la raíz del proyecto en vez de en `backend/app/`

### 4.2 Código Acoplado y No Escalable

- **[api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py) conoce demasiado**: Maneja directamente sanitización de filenames, path validation, upload streaming, y dispatch de N8N — todo debería estar en capas separadas
- **Doble cliente N8N**: Existe [core/automation/n8n_client.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/automation/n8n_client.py) (wrapper muerto de 2 líneas) y [core/integrations/n8n_client.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/integrations/n8n_client.py) (el real). Confuso y redundante
- **[LLMAgentBridge](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/llm_agent_bridge.py#69-170) es un adapter innecesario**: Existe solo por "compatibilidad retroactiva" pero agrega una capa de indirección sin valor; [ExplanationService](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/llm/explanation_service.py#91-153) podría usarse directamente
- **Clasificación binaria hardcodeada**: Solo `MALWARE`/`BENIGN` con un threshold fijo (0.5). El PRD requiere tres niveles con la adición de `suspicious`

### 4.3 Violaciones de Buenas Prácticas

| Problema | Ubicación | Detalle |
|----------|-----------|---------|
| Globals mutables | `api_server.py:32-34` | `engine`, [telemetry](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py#71-80), `n8n_client` son módulos-nivel sin Depends |
| f-strings en logging | `engine.py:74`, `inference.py:39` | Usar `logger.info("Msg: %s", var)` en vez de f-strings por rendimiento |
| Falta validación de entrada | `api_server.py:176-178` | [scan_ngrok()](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py#175-234) acepta `Dict` sin Pydantic: cualquier payload pasa |
| URLs hardcodeadas | `n8n_client.py:32-33` | URLs de ngrok están en constantes del código, no en `.env` |
| Sin `.env` real | Raíz del proyecto | Solo existe [.env.test](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/.env.test); PRD menciona `.env` como parte de la estructura |
| Falta CORS | [api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py) | Sin `CORSMiddleware` — el frontend Electron no podrá acceder |
| Type hints incompletos | Varios archivos | Muchos `Dict` sin tipado específico; falta `-> None` en algunos métodos |
| Sin docstrings en endpoints | [api_server.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/api_server.py) | Endpoints no tienen docstrings descriptivos para OpenAPI |

### 4.4 Seguridad

- **Sin CORS**: La API acepta requests de cualquier origen sin configuración, o fallan silenciosamente desde el frontend
- **Upload sin validación MIME**: Solo se valida tamaño, no tipo de archivo
- **Información sensible en respuestas de error**: Se exponen excepciones crudas ([str(exc)](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/integrations/n8n_client.py#114-124)) al cliente
- **Sin rate limiting**: Los endpoints no tienen protección contra abuso

---

## 5. Recomendaciones Técnicas

### 5.1 Reestructuración del Proyecto

```
backend/
└── app/
    ├── main.py                      # FastAPI app + middleware (CORS)
    ├── api/
    │   ├── routes/scan.py           # Rutas: /scan/file, /scan/multiple, /scan/realtime
    │   ├── routes/analysis.py       # Ruta: /analysis/explain
    │   ├── routes/health.py         # Ruta: /health
    │   ├── controllers/scan_controller.py
    │   ├── controllers/analysis_controller.py
    │   └── dependencies/            # Depends() para engine, services
    ├── services/
    │   ├── scan_service.py          # Orquesta scan: validate → extract → predict → label
    │   ├── analysis_service.py      # Refactor de scan_pipeline.py
    │   ├── llm_service.py           # Refactor de explanation_service.py
    │   └── realtime_service.py      # NUEVO: monitoreo de procesos
    ├── schemas/dto.py               # NUEVO: Pydantic models (request/response)
    ├── models/ml_model.py           # Mover inference.py
    ├── integrations/
    │   ├── supabase_client.py       # NUEVO: Persistencia
    │   ├── n8n_client.py            # Mover de core/integrations/
    │   └── ollama_client.py         # Mover de core/llm/
    ├── utils/
    │   ├── file_utils.py            # NUEVO: validación, sanitización
    │   ├── logger.py                # Mover de utils/
    │   └── security.py              # NUEVO: CORS config, rate limiting
    └── config/settings.py           # Ampliar con Supabase, CORS, etc.
```

### 5.2 Definir Schemas con Pydantic

Crear DTOs para entrada y salida:

- `ScanFileRequest` (POST body con archivo)
- `ScanMultipleRequest` (lista de archivos)
- `ExplainRequest` (scan_result o file_path)
- `ScanResponse` (formato del PRD sección 19.1)
- `ErrorResponse` (formato estandarizado sección 19.7)

### 5.3 Corregir Rutas de Endpoints

| Actual | Correcto (PRD) | Acción |
|--------|----------------|--------|
| `GET /scan-file` | `POST /scan/file` | Cambiar método + ruta + recibir archivo vía `UploadFile` |
| `POST /scan-batch` | `POST /scan/multiple` | Renombrar ruta |
| `POST /llm/explain` | `POST /analysis/explain` | Renombrar ruta |
| No existe | `GET /scan/realtime` | Implementar monitoreo de procesos |

### 5.4 Implementar Supabase

- Instalar `supabase-py`
- Crear `supabase_client.py` con operaciones: `save_scan_result()`, `get_history()`, `sync_offline_pending()`
- Persistir después del paso de clasificación, según el flujo del PRD

### 5.5 Implementar Modo Offline

- Detectar conectividad (Supabase, red)
- Si offline: omitir LLM, Supabase, N8N; marcar `"mode": "offline"` en response
- Guardar resultados pendientes en SQLite local o JSONL
- Sincronizar al reconectar

### 5.6 Agregar CORS

```python
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"], ...)
```

### 5.7 Webhook Condicional para N8N

El PRD especifica: N8N solo se activa cuando `result == "malicious"`. Actualmente se envía siempre. Agregar condición en el pipeline.

### 5.8 Clasificación Tripartita

Cambiar de binario (`MALWARE`/`BENIGN`) a tres niveles:

| Score | Clasificación |
|-------|--------------|
| `< 0.35` | `benign` |
| `0.35 – 0.65` | `suspicious` |
| `> 0.65` | `malicious` |

---

## 6. Plan de Acción Priorizado

### 🔴 Prioridad Crítica (Bloqueante para funcionalidad del PRD)

| # | Tarea | Impacto |
|---|-------|---------|
| 1 | **Crear schemas/DTOs con Pydantic** para request y response (formato PRD s.19) | Validación de entrada, documentación OpenAPI, respuestas estandarizadas |
| 2 | **Corregir rutas y métodos HTTP** de endpoints (`/scan/file` POST, `/scan/multiple` POST, `/analysis/explain` POST) | Cumplir contrato del PRD para que frontend funcione |
| 3 | **Agregar CORSMiddleware** con orígenes configurables | Sin esto, el frontend Electron no puede comunicarse |
| 4 | **Implementar clasificación tripartita** (benign/suspicious/malicious) con campo [risk_level](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/integrations/n8n_client.py#73-82) | El PRD requiere tres niveles, no dos |
| 5 | **Implementar `supabase_client.py`** + persistencia de resultados | Requisito fundamental del PRD: todo escaneo se persiste |

### 🟠 Prioridad Alta (Requerido por el PRD)

| # | Tarea | Impacto |
|---|-------|---------|
| 6 | **Condicionar N8N a `result == "malicious"`** solamente | El PRD lo especifica en sección 19.5 |
| 7 | **Implementar `GET /scan/realtime`** (monitoreo de procesos con `psutil`) | Funcionalidad completa del PRD |
| 8 | **Estandarizar formato de respuesta** al frontend (s.19.6) con `status`, [data](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/models/best_model.onnx.data), manejo de errores (s.19.7) | Contrato frontend-backend consistente |
| 9 | **Implementar modo offline** (detección, flag, cola de sincronización) | Requisito core del producto |
| 10 | **Reestructurar proyecto** a `backend/app/` con separación routes/controllers/services | Cumplir arquitectura del PRD |

### 🟡 Prioridad Media (Calidad y mantenibilidad)

| # | Tarea | Impacto |
|---|-------|---------|
| 11 | **Usar `Depends()` de FastAPI** para inyección de engine, services | Testabilidad, desacoplamiento |
| 12 | **Crear `utils/file_utils.py`** y `utils/security.py` | Reutilización, separación de concerns |
| 13 | **Eliminar [core/automation/n8n_client.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/automation/n8n_client.py)** (duplicado muerto) | Limpieza |
| 14 | **Evaluar si [LLMAgentBridge](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/llm_agent_bridge.py#69-170) es necesario** o si [ExplanationService](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/core/llm/explanation_service.py#91-153) debe usarse directamente | Reducir indirección innecesaria |
| 15 | **Agregar docstrings a endpoints** para OpenAPI/Swagger | Documentación auto-generada |

### 🟢 Prioridad Baja (Nice-to-have, mejoras incrementales)

| # | Tarea | Impacto |
|---|-------|---------|
| 16 | **Reemplazar f-strings en logging** por `%s` formatting | Rendimiento marginal |
| 17 | **Mover URLs de ngrok a `.env`** en vez de constantes hardcodeadas | Configurabilidad |
| 18 | **Agregar rate limiting** a endpoints | Seguridad adicional |
| 19 | **Ampliar `/health`** para reportar estado de Ollama, Supabase, N8N | Observabilidad operativa |
| 20 | **Agregar validación MIME/magic bytes** en uploads | Seguridad adicional |

---

> [!IMPORTANT]
> **Hallazgo principal:** El backend tiene la lógica de negocio core funcional (modelo ML, extractores, Ollama, N8N) pero no cumple la arquitectura del PRD. Los 5 puntos más críticos son: **schemas/DTOs**, **rutas correctas**, **CORS**, **clasificación tripartita** y **Supabase** — sin estos, el flujo completo definido en el PRD no puede funcionar.
