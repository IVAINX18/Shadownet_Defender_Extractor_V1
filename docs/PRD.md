# ShadowNet Defender — Product Requirements Document (PRD)

---

## 1. Overview

**ShadowNet Defender** es una aplicación de ciberseguridad basada en inteligencia artificial para la detección de malware mediante análisis estático, comportamental y aprendizaje automático.

El sistema está diseñado como una **aplicación de escritorio multiplataforma** (Linux/Windows) con capacidades offline, integrando modelos locales y servicios automatizados.

---

## 2. Objetivo del Producto

Desarrollar una herramienta:

- Capaz de detectar malware con alta precisión
- Que funcione sin conexión a internet (**offline-first**)
- Que explique sus decisiones mediante IA (LLM)
- Escalable, mantenible y entendible por desarrolladores junior

---

## 3. Arquitectura del Sistema

### 3.1 Enfoque General

Arquitectura **monorepo desacoplada**, con backend y frontend separados pero dentro del mismo repositorio.

- Backend local embebido
- Frontend en Electron
- Comunicación vía HTTP (localhost)

### 3.2 Estructura del Monorepo

```
shadownet-defender/
│
├── backend/
├── frontend/
├── docs/
├── scripts/
├── .env
└── README.md
```

---

## 4. Backend (FastAPI)

### 4.1 Responsabilidades

- Procesamiento de archivos
- Ejecución del modelo ML
- Integración con LLM (Ollama)
- Comunicación con N8N
- Persistencia en Supabase
- Monitoreo en tiempo real

### 4.2 Estructura Interna

```
backend/
│
├── app/
│   ├── main.py
│
│   ├── api/
│   │   ├── routes/
│   │   ├── controllers/
│   │   └── dependencies/
│
│   ├── services/
│   │   ├── scan_service.py
│   │   ├── analysis_service.py
│   │   ├── llm_service.py
│   │   └── realtime_service.py
│
│   ├── models/
│   │   └── ml_model.py
│
│   ├── schemas/
│   │   └── dto.py
│
│   ├── utils/
│   │   ├── file_utils.py
│   │   ├── logger.py
│   │   └── security.py
│
│   ├── integrations/
│   │   ├── supabase_client.py
│   │   ├── n8n_client.py
│   │   └── ollama_client.py
│
│   └── config/
│       └── settings.py
│
├── tests/
├── requirements.txt
└── .env
```

### 4.3 Endpoints

#### Escaneo

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/scan/file` | Escaneo de un archivo individual |
| `POST` | `/scan/multiple` | Escaneo de múltiples archivos |

**Funciones:**
- Validar archivo
- Extraer características
- Ejecutar modelo ML

#### Análisis en Tiempo Real

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/scan/realtime` | Monitoreo de procesos activos |

**Funciones:**
- Monitorear procesos
- Detectar comportamiento anómalo

#### Explicación

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/analysis/explain` | Generar explicación con Ollama |

**Funciones:**
- Enviar resultado a Ollama
- Generar explicación detallada

#### Salud del Sistema

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/health` | Estado del backend |

### 4.4 Flujo Interno

```
1. Recepción de archivo
2. Validación de seguridad
3. Extracción de features
4. Inferencia del modelo
5. Clasificación:
   ├── Benigno
   ├── Sospechoso
   └── Malicioso
6. Generación de explicación (LLM)
7. Persistencia en Supabase
8. Activación de N8N
```

---

## 5. Modelo de Machine Learning

### 5.1 Estado Actual

- Implementado en **PyTorch**
- Dataset: **SOREL**
- Entrenamiento con **Early Stopping**

### 5.2 Requisitos

- Exportable (ONNX recomendado)
- Carga eficiente en memoria
- Inferencia rápida (**< 2 segundos**)

### 5.3 Integración

- Debe ser llamado desde `scan_service`
- No debe estar acoplado al endpoint directamente

---

## 6. LLM (Ollama)

### 6.1 Función

Explicar los resultados generados por el modelo ML.

### 6.2 Requisitos

- Funcionamiento **local**
- Prompt estructurado
- Respuesta clara y técnica

### 6.3 Ejemplo de Prompt

```
Analiza el siguiente resultado de detección de malware:

Resultado: Malicioso
Confianza: 92%
Características detectadas: [lista]

Explica de forma técnica:
- Por qué se considera malicioso
- Qué riesgos representa
- Recomendaciones
```

---

## 7. Automatización (N8N)

### 7.1 Funciones

- Envío de alertas (Gmail)
- Registro en Google Drive

### 7.2 Integración

- Trigger mediante **webhook** desde el backend

---

## 8. Base de Datos (Supabase)

### 8.1 Datos Almacenados

| Campo | Tipo |
|-------|------|
| `usuario_id` | string |
| `nombre_archivo` | string |
| `resultado` | enum |
| `confianza` | float |
| `explicacion` | text |
| `fecha` | datetime |
| `tiempo_escaneo` | float |

---

## 9. Frontend (React + Electron)

### 9.1 Responsabilidades

- Interfaz de usuario
- Comunicación con backend
- Visualización de resultados
- Gestión de estado

### 9.2 Estructura

```
frontend/
│
├── src/
│   ├── components/
│   ├── pages/
│   ├── services/
│   │   └── api.js
│   ├── hooks/
│   ├── context/
│   └── utils/
│
├── electron/
│   └── main.js
│
└── package.json
```

### 9.3 Vistas

- Dashboard
- Escaneo de archivos
- Resultados
- Historial

---

## 10. Modo Offline

### 10.1 Características

- Uso de modelo local
- Sin conexión a Supabase
- Sin N8N

### 10.2 Sincronización

Envío de datos pendientes cuando se restaure la conexión.

---

## 11. Seguridad

- Validación de archivos
- Sanitización de inputs
- No ejecución de archivos analizados
- Uso de variables de entorno
- Configuración de CORS

---

## 12. Estándares de Código

- Python: **PEP8**
- Uso de **type hints**
- Código **modular**
- Comentarios en primera persona:
  - Explico qué hace
  - Explico por qué

---

## 13. Estado del Proyecto

### ✅ Implementado

- Modelo ML (PyTorch)
- Dataset SOREL
- Early Stopping
- Integración con Ollama
- Automatización con N8N

### 🔲 Pendiente

#### Backend
- [ ] API completa en FastAPI
- [ ] Integración total del modelo
- [ ] Logs estructurados

#### Frontend
- [ ] UI completa
- [ ] Integración con Electron

#### Integraciones
- [ ] Supabase completo
- [ ] Webhooks N8N

#### Offline
- [ ] Micro modelo local
- [ ] Sincronización

---

## 14. Flujo Completo del Sistema

```
1. Usuario selecciona archivo
2. Frontend envía request a FastAPI
3. Backend ejecuta modelo ML
4. Resultado enviado a Ollama
5. Se genera explicación
6. Se guarda en Supabase
7. Se dispara N8N (si es malicioso)
8. Se muestra resultado en UI
```

---

## 15. Reglas para IDEs con IA

- No recrear el modelo ML — **integrar el existente**
- Usar Ollama local
- Mantener separación de capas
- No mezclar frontend y backend
- Seguir la estructura definida
- Generar código escalable y modular
- Implementar manejo de errores
- Documentar funciones con docstrings

---

## 16. Métricas de Éxito

| Métrica | Objetivo |
|---------|----------|
| Precisión del modelo | > 90% |
| Tiempo de respuesta | < 2 segundos |
| Latencia en UI | Baja |
| Calidad de explicaciones | Claras y técnicas |
| Mantenibilidad | Accesible para juniors |

---

## 17. Estrategia de Despliegue

- Backend ejecutándose **localmente** (FastAPI)
- Frontend empaquetado con **Electron**
- Comunicación por **localhost**
- Sin dependencia obligatoria de internet

---

## 18. Siguientes Pasos Técnicos

1. Crear estructura backend
2. Implementar `/scan/file`
3. Integrar modelo ML
4. Conectar Ollama
5. Integrar Supabase
6. Conectar N8N
7. Crear UI básica
8. Integrar Electron

---

## 19. Salida / Resultado Esperado

### 19.1 Resultado del Escaneo (Output Principal)

Cada escaneo debe generar el siguiente objeto estructurado:

```json
{
  "file_name": "example.exe",
  "scan_type": "single | multiple | realtime",
  "result": "benign | suspicious | malicious",
  "confidence": 0.92,
  "scan_time": "1.34s",
  "features_detected": [],
  "timestamp": "ISO8601",
  "explanation": "string",
  "risk_level": "low | medium | high"
}
```

### 19.2 Interpretación del Resultado

| Resultado | Significado |
|-----------|-------------|
| `benign` | El archivo no presenta comportamiento malicioso detectable. |
| `suspicious` | El archivo contiene patrones inusuales que requieren revisión. |
| `malicious` | El archivo presenta características asociadas a malware conocido o comportamiento dañino. |

### 19.3 Explicación Generada (LLM)

El sistema debe retornar una explicación estructurada generada por Ollama que incluya:

- Motivo de la clasificación
- Características relevantes detectadas
- Posibles riesgos
- Recomendaciones de acción

**Ejemplo esperado:**

> El archivo ha sido clasificado como malicioso debido a la presencia de patrones comunes en ejecutables que intentan modificar el registro del sistema y establecer persistencia. Se recomienda eliminar el archivo y realizar un análisis completo del sistema.

### 19.4 Salida hacia Supabase

| Campo | Descripción |
|-------|-------------|
| `file_name` | Nombre del archivo analizado |
| `result` | Resultado de la clasificación |
| `confidence` | Nivel de confianza del modelo |
| `explanation` | Explicación generada por Ollama |
| `scan_time` | Tiempo de escaneo |
| `timestamp` | Fecha y hora del escaneo |
| `user_id` | Identificador del usuario |

### 19.5 Activación de N8N

**Condición de activación:** `result == "malicious"`

**Acciones esperadas:**

- Envío de correo al usuario
- Registro en Google Drive
- Notificación estructurada con:
  - Nombre del archivo
  - Nivel de riesgo
  - Resumen del análisis

### 19.6 Respuesta del Backend al Frontend

```json
{
  "status": "success",
  "data": {
    "file_name": "example.exe",
    "result": "malicious",
    "confidence": 0.92,
    "risk_level": "high",
    "explanation": "..."
  }
}
```

**Requisitos de respuesta:**
- Formato JSON estandarizado
- Tiempo de respuesta **< 2 segundos** (ideal)
- Manejo de errores incluido

### 19.7 Manejo de Errores

```json
{
  "status": "error",
  "message": "Invalid file type",
  "code": 400
}
```

### 19.8 Visualización en Frontend

El frontend debe mostrar:

- Estado del archivo (colorizado: 🟢 verde, 🟡 amarillo, 🔴 rojo)
- Nivel de riesgo
- Explicación detallada
- Tiempo de escaneo
- Historial del usuario

### 19.9 Resultado en Modo Offline

- Retornar resultado **sin explicación LLM** (opcional)
- Marcar como `"mode": "offline"`
- Sin envío a Supabase ni N8N
- Sincronización posterior cuando haya conexión

### 19.10 Criterios de Aceptación

Un escaneo se considera **exitoso** si:

- [x] Se obtiene clasificación válida
- [x] Se genera explicación (si hay conexión)
- [x] Se almacena correctamente (modo online)
- [x] Se muestra correctamente en el frontend

---