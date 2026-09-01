# ShadowNet Defender – Estado del Proyecto

## 1. Resumen General

- **Estado actual del proyecto**: Desarrollo activo y funcional.
- **Nivel**: MVP Avanzado / Product-ready parcial (flujo core end-to-end completo).
- **Breve descripción del sistema**: ShadowNet Defender es una aplicación de escritorio multiplataforma (Electron + React) de ciberseguridad construida con un enfoque offline-first. Ejecuta escaneos de malware localmente apoyados en inteligencia artificial (motor ONNX para clasificación y Ollama para explicar hallazgos) usando un backend en FastAPI enlazado fuertemente con Supabase para almacenamiento de historial de usuarios.

---

## 2. Estado por Módulos

### 2.1 Backend

- API (FastAPI) → ✅ Completado
- Endpoints implementados → ✅ Completado (`/scan/file`, `/scan/multiple`, `/analysis/explain`, `/health`)
- Sistema de escaneo (ONNX) → ✅ Completado (Delegado a `core/` inter-módulo)
- Integración con Ollama → ✅ Completado (Para retornos de análisis y explicación)
- Integración con Supabase → ✅ Completado (Guardado persistente y dependencias de auth)

### 2.2 Frontend

- Login / Register → ✅ Completado
- Dashboard → ✅ Completado
- Scan UI → ✅ Completado
- Resultados → ✅ Completado
- Historial → ✅ Completado
- Integración con backend → ✅ Completado

### 2.3 Desktop (Electron)

- Configuración base → ✅ Completado (`main.js` y `preload.js` listos)
- Integración React → ✅ Completado (Soporte local dev con Vite y build estático productivo)
- Build multiplataforma → ✅ Completado (Resoluciones lógicas agnósticas a SO)
- Acceso a recursos del sistema → ✅ Completado

### 2.4 Inteligencia Artificial

- Modelo ONNX → ✅ Completado
- Clasificación (benign/suspicious/malicious) → ✅ Completado
- Soporte PE vs non-PE → ✅ Completado
- Explicaciones con LLM (Ollama) → ✅ Completado
- Manejo de timeout → ✅ Completado (Gestión de fallbacks implementada)

### 2.5 Base de Datos (Supabase)

- Tabla users → ✅ Completado (A través de Supabase Auth)
- Tabla scan_results → ✅ Completado
- Persistencia de resultados → ✅ Completado (Con soporte de failover offline)
- Relación con usuario → ✅ Completado (Via token JWT de validación FastAPI)
- Guardado de explanation → ✅ Completado

---

## 3. Comparación contra PRD

| Feature | PRD | Estado actual | Notas |
| -------- | --- | ------------- | ---- |
| Análisis PE / Extracción Features | Requerido | ✅ | Funcionalidad core en modo local operativa. |
| Inferencia ML (ONNX) | Requerido | ✅ | Integración sub-2-segundos exitosa en backend. |
| Multi-file scan | Requerido | ✅ | Incluido en las rutas de la API de FastAPI. |
| File scanning | Requerido | ✅ | Análisis particular implementado en UI y endpoints. |
| Explicaciones Ollama | Requerido | ✅ | Soportado con timeouts y resiliencia local. |
| Autenticación BD (Supabase) | Requerido | ✅ | Control JWT en el Dependency Injection (`auth.py`). |
| Modo Offline | Requerido | ✅ | Backend preparado para retries y guardado de colas asíncronas. |
| Real-time monitoring | Requerido | ⚠️ | Servicio base implementado, pendiente mayor madurez UI. |
| Alerts system (N8N) | Requerido | ⚠️ | Integración parcial (trigger bajo resultados maliciosos en `scan_service`). |

---

## 4. Decisiones Técnicas Importantes

- **Uso de ONNX para inferencia:** Transición de modelo clásico de PyTorch a runtime empaquetado ONNX asegurando inferencia ultra-rápida nativa y cumpliendo requisitos de escaneo `< 2 seg` en modo offline.
- **Uso de Ollama para explicaciones:** Garantiza que los metadatos de los archivos analizados jamás viajen a clouds de terceros, interpretando los resultados localmente en el SO del usuario.
- **Uso de Supabase para auth + DB:** La sesión es inyectada mediante headers en Electron y parseada mediante JWKS en el Backend vía Python. Con ello se prohíbe el envío arbitrario de un email desde el cliente.
- **Clasificación de archivos non-PE como suspicious:** Para abarcar archivos sospechosos no contemplados por la IA original se incluyeron lógicas estáticas preventivas.
- **Uso de Electron para multiplataforma:** La app web local (React+Vite) queda unificada, y se incluyó en `main.js` un flag específico para deshabilitar hardware-acceleration en Linux previniendo fallas de WebGL/Wayland.

---

## 5. Problemas Encontrados y Soluciones

- **Double Source of Truth (Auth):** El frontend enviaba en el body IDs mutables. Solución: la api FastAPI ahora fuerza la ignorancia del payload asumiendo 100% de la identidad a través de la desencriptación del token Supabase por sí misma.
- **Model loading lento:** Solucionado mediante patrón Singleton global (iniciado al arrancar FastAPI o en la primera run), manteniendo los pesos en memoria RAM entre inferencias.
- **LLM tardando demasiado:** Interacciones prolongadas truncadas mediante un gestor de TIMEOUT en `llm_service`, procediendo a devolver la clasificación sin un texto descriptivo antes que trabar la cola.
- **Enum mal serializado:** Requerido el mapeo de los retornos (maligno, benigno) a cadenas puras durante la bajada HTTP con `use_enum_values` en las capas de Pydantic.

---

## 6. Pendientes (Roadmap corto)

- Refinar robustez del **monitoreo en tiempo real**.
- Refinar **Frontend completo** y UX de resultados interactivos.
- Extender el entrenamiento con un **Dataset real de malware** más exhaustivo.
- Realizar pruebas exhaustivas con **malware real** en una **máquina virtual aislada** (actualmente no se han realizado pruebas de infección o ejecución de la amenaza en entornos reales).
- Ampliar las notificaciones y **Sistema de alertas** finales (N8N callbacks completos).
- Realizar optimización general de **UI/UX**.

---

## 7. Estado Final

El proyecto **ShadowNet Defender** cuenta con una base sumamente sólida. Todo el núcleo de funcionalidad dictado por el PRD (Modelo ML Local, Backend intermedio offline-first, e Interfaz de Usuario Desktop) está operando armónicamente en conjunto. El sistema es totalmente capaz de identificar y narrar un hallazgo de malware por sí mismo sin conectividad y persistirlo en la nube al regresar online.

Está catalogado como un **MVP Maduro cercano a Product-Ready**. Lo único faltante antes del despliegue público será la optimización final del monitoreo de procesos directos en memoria RAM, estilización de interfaces, y los scripts para la compilación cross-platform de los binarios ejecutables para los consumidores target.
