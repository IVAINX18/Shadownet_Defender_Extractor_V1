# Documento de Requisitos — ShadowNet Defender: Mejoras de Auditoría

## Introducción

Este documento recoge los requisitos para implementar las mejoras identificadas en la auditoría integral de ShadowNet Defender. El objetivo es elevar el sistema desde su estado actual de **prototipo funcional** hasta un nivel de **prueba controlada en laboratorio** (Pilot Ready), abordando los hallazgos críticos (P0/P1) y prioritarios (P2/P3) detectados en la auditoría.

El código real inspeccionado revela:
- **Pipeline de detección estático**: IMPLEMENTADO / INTEGRADO (YARA → UPX → ML/ONNX → Overlay → DotNet → IL → Risk Engine)
- **Process Monitor (BehavioralShield)**: IMPLEMENTED BUT NOT INTEGRATED — `process_monitor.py` existe con psutil pero NO está conectado al pipeline de `scan_file()` ni al Risk Engine
- **Cuarentena/Aislamiento**: NOT IMPLEMENTED — no existe ningún módulo de quarantine
- **Remediación/Terminación de procesos**: NOT IMPLEMENTED
- **Backend FastAPI**: IMPLEMENTED / INTEGRATED — con autenticación JWT, Supabase, n8n
- **Persistencia Supabase**: PARTIALLY IMPLEMENTED — guarda datos limitados, falta `operational_status`, `overlay_analysis`, `yara_matches` completo, `il_behavioral`
- **n8n**: PARTIALLY IMPLEMENTED — solo envía para `result == "malicious"`, no para `operational_status == "DANGEROUS"`
- **Cola offline**: IMPLEMENTED / INTEGRATED — `offline_service.py` con fallback JSON
- **Tests**: NOT IMPLEMENTED — no existe directorio de tests con cobertura real
- **Despliegue**: NOT IMPLEMENTED — no hay servicio Windows/systemd Linux

---

## Glosario

- **Pipeline**: Cadena de análisis YARA → UPX → ML/ONNX → Overlay → DotNet → IL → Risk Engine
- **Engine**: `core/engine.py` — `ShadowNetEngine`, punto central de orquestación
- **Extractor**: `extractors/extractor.py` — `PEFeatureExtractor`, extrae 2381 features
- **BehavioralShield**: `core/dynamic/process_monitor.py` — monitor de procesos activos con psutil
- **Risk_Engine**: `core/heuristics/` — `HeuristicRiskEngine`, produce `operational_status` / `risk_level` / `risk_score`
- **IL_Analyzer**: `core/dotnet/il_analyzer.py` — análisis semántico de código IL .NET
- **DotNet_Analyzer**: `core/dotnet/__init__.py` — análisis de CLR header y metadatos .NET
- **Supabase_Client**: `backend/app/integrations/supabase_client.py`
- **N8N_Client**: `core/integrations/n8n_client.py`
- **Quarantine_Manager**: módulo a implementar para aislamiento seguro de archivos maliciosos
- **Remediation_Engine**: módulo a implementar para terminación de procesos y limpieza de persistencia
- **Scan_Service**: `backend/app/services/scan_service.py`
- **Operational_Status**: campo de salida del Risk Engine — `CLEAN` | `SUSPICIOUS` | `DANGEROUS`
- **RAW_FALLBACK**: modo degradado del Extractor cuando pefile falla
- **SOREL-20M**: modelo ONNX de 2381 features — NO modificar el vector ni el modelo
- **DANGEROUS**: valor de `operational_status` que indica amenaza confirmada por capas heurísticas
- **PE**: Portable Executable — formato de binario Windows analizable por el pipeline
- **UPX**: compresor de ejecutables — detectado y desempacado en Fase 2 del Engine

---

## Requisitos

---

### Requisito 1 — Integración del BehavioralShield en el Pipeline Principal

**User Story:** Como analista de seguridad, quiero que el análisis de procesos activos esté integrado en el pipeline principal de detección, para que el `operational_status` refleje comportamiento dinámico observable y no solo análisis estático.

#### Criterios de Aceptación

1. CUANDO `scan_file()` reciba un `file_path` cuyo ejecutable esté activo como proceso en el sistema, EL Engine DEBERÁ invocar `BehavioralShield.analyze_process()` como Fase 7 del pipeline y fusionar el `BehaviorReport` con el resultado existente.
2. SI `BehaviorReport.risk_score >= 0.5` Y `operational_status` es `CLEAN` o `SUSPICIOUS`, ENTONCES EL Engine DEBERÁ elevar `operational_status` a `DANGEROUS` e incluir las `suspicious_actions` en el campo `details`.
3. SI `BehaviorReport.risk_score >= 0.3` Y `operational_status` es `CLEAN`, ENTONCES EL Engine DEBERÁ elevar `operational_status` a `SUSPICIOUS`.
4. SI psutil no está disponible o el proceso no está activo, EL Engine DEBERÁ continuar el pipeline sin error y registrar el motivo en los logs.
5. EL Engine DEBERÁ resolver el PID del proceso activo mediante comparación de `executable path` normalizado entre la lista de `psutil.process_iter()` y el `file_path` del escaneo.
6. EL `Scan_Service` DEBERÁ incluir el campo `behavioral_analysis` en el `ScanResult` con el `BehaviorReport` serializado o `null` si el proceso no estaba activo.
7. MIENTRAS se ejecute el monitoreo dinámico, EL Engine DEBERÁ aplicar un timeout de 2 segundos para que la fase dinámica no bloquee el pipeline estático.

---

### Requisito 2 — Módulo de Cuarentena Segura (Quarantine Manager)

**User Story:** Como operador de seguridad, quiero aislar archivos maliciosos detectados en un directorio de cuarentena seguro, para que no puedan ejecutarse accidentalmente mientras se preserva la evidencia forense.

#### Criterios de Aceptación

1. EL `Quarantine_Manager` DEBERÁ implementar una función `quarantine_file(file_path, scan_result)` que mueva el archivo a un directorio configurable `QUARANTINE_DIR` (default: `~/.shadownet/quarantine/`).
2. CUANDO se cuarentene un archivo, EL `Quarantine_Manager` DEBERÁ renombrarlo con el formato `{SHA256_8CHARS}_{timestamp}.quar` para evitar colisiones de nombres y ejecución accidental.
3. EL `Quarantine_Manager` DEBERÁ calcular y almacenar el SHA-256 del archivo original ANTES de moverlo, guardando los metadatos en un archivo `{SHA256_8CHARS}_{timestamp}.meta.json` junto al archivo en cuarentena.
4. CUANDO se mueva un archivo, EL `Quarantine_Manager` DEBERÁ remover los permisos de ejecución del archivo en cuarentena (chmod a-x en Linux; eliminar bit ejecutable en Windows).
5. IF el archivo fuente es un symlink o hardlink, THEN EL `Quarantine_Manager` DEBERÁ rechazar la operación y retornar un error `SYMLINK_REJECTED` para evitar ataques TOCTOU.
6. IF el `file_path` contiene secuencias de path traversal (`..`, rutas absolutas fuera del scope configurado), THEN EL `Quarantine_Manager` DEBERÁ rechazar la operación y retornar `PATH_TRAVERSAL_REJECTED`.
7. EL `Quarantine_Manager` DEBERÁ implementar `restore_file(quarantine_path, destination)` para restaurar archivos con verificación de integridad SHA-256.
8. PARA TODA operación de cuarentena, EL `Quarantine_Manager` DEBERÁ registrar en logs: timestamp, sha256, tamaño, origen, destino, usuario que inició la acción y resultado.
9. IF `QUARANTINE_DIR` no existe, THEN EL `Quarantine_Manager` DEBERÁ crearlo con permisos restrictivos (700 en Linux).
10. EL Backend DEBERÁ exponer `POST /quarantine/file` que reciba `file_path` y `scan_id`, delegue a `Quarantine_Manager.quarantine_file()`, y retorne el estado de la operación.

---

### Requisito 3 — Remediación: Terminación de Procesos Maliciosos

**User Story:** Como operador de seguridad, quiero poder terminar procesos identificados como maliciosos, para contener una infección activa en el endpoint.

#### Criterios de Aceptación

1. EL `Remediation_Engine` DEBERÁ implementar `terminate_process(pid, reason, scan_id)` que intente terminar el proceso con `SIGTERM` (Linux) o `TerminateProcess()` (Windows).
2. CUANDO se solicite terminación, EL `Remediation_Engine` DEBERÁ verificar primero que el PID corresponde al ejecutable analizado mediante comparación de `exe_path` antes de terminar.
3. IF la terminación con SIGTERM falla tras 3 segundos, THEN EL `Remediation_Engine` DEBERÁ escalar a SIGKILL en Linux o `TerminateProcess` con código de salida 1 en Windows.
4. EL `Remediation_Engine` DEBERÁ registrar en logs: PID, nombre del proceso, exe_path, método de terminación, timestamp, resultado y el `scan_id` asociado.
5. IF el proceso objetivo es un proceso protegido del sistema operativo (PID < 10 en Linux, procesos de sesión 0 en Windows), THEN EL `Remediation_Engine` DEBERÁ rechazar la operación y retornar `PROTECTED_PROCESS_REJECTED`.
6. EL Backend DEBERÁ exponer `POST /remediation/terminate` con autenticación JWT obligatoria, que reciba `pid` y `scan_id` y retorne el resultado de la terminación.
7. MIENTRAS se ejecute la terminación, EL `Remediation_Engine` DEBERÁ capturar y registrar cualquier excepción de permisos (`PermissionError`, `psutil.AccessDenied`) sin propagar al caller.

---

### Requisito 4 — Esquema Supabase Extendido y Persistencia Completa

**User Story:** Como analista SOC, quiero que todos los campos de telemetría del pipeline sean persistidos en Supabase, para poder auditar y correlacionar incidentes completos desde el dashboard.

#### Criterios de Aceptación

1. EL `Supabase_Client` DEBERÁ guardar en la tabla `scan_results` los campos: `operational_status`, `risk_score`, `risk_level`, `overlay_analysis` (JSON), `yara_matches` (JSON array), `il_behavioral` (JSON), `dotnet_analysis` (JSON), `was_unpacked`, `detection_phases` (JSON array), `is_dotnet`, `obfuscator_detected`, `obfuscator_name`, `injection_detected`, `persistence_detected`, `networking_detected`, `credential_theft_detected`.
2. CUANDO `save_scan()` procese un resultado con `operational_status == "DANGEROUS"`, EL `Supabase_Client` DEBERÁ además insertar un registro en la tabla `incidents` con `severity = "critical"`, `file_name`, `scan_id` y `timestamp`.
3. IF la inserción en Supabase falla por timeout (> 5s) o error de red, THEN EL `Supabase_Client` DEBERÁ encolar el resultado en `offline_service.queue_scan()` sin lanzar excepción al caller.
4. EL `Supabase_Client` DEBERÁ implementar idempotencia basada en `sha256` del archivo: si ya existe un registro con el mismo sha256 y timestamp dentro de los últimos 60 segundos, DEBERÁ retornar el registro existente sin insertar duplicado.
5. EL `Supabase_Client` DEBERÁ agregar el campo `sha256` al registro de `scan_results`, calculado en el `Scan_Service` antes de llamar a `save_scan()`.
6. PARA TODO campo de tipo JSON/JSONB, EL `Supabase_Client` DEBERÁ serializar con `json.dumps()` y manejar valores `NaN` / `Inf` sustituyéndolos por `null` antes de enviar.

---

### Requisito 5 — Alertas N8N para DANGEROUS y Modo Fallback

**User Story:** Como operador SOC, quiero recibir alertas de n8n para cualquier amenaza confirmada, no solo cuando el label ML es "malicious", para que amenazas detectadas por heurísticas o IL sean notificadas correctamente.

#### Criterios de Aceptación

1. CUANDO `operational_status == "DANGEROUS"`, EL `N8N_Client` DEBERÁ enviar una alerta al webhook configurado, independientemente del valor de `result` (label ML).
2. EL `N8N_Client` DEBERÁ incluir en el payload de alerta los campos: `operational_status`, `risk_score`, `risk_level`, `detection_phases`, `top_family`, `injection_detected`, `persistence_detected`, además de los campos existentes.
3. CUANDO `result == "malicious"` Y `operational_status != "DANGEROUS"`, EL `N8N_Client` DEBERÁ seguir enviando la alerta con el payload extendido (comportamiento actual preservado).
4. IF el webhook de n8n retorna un código HTTP >= 500, THEN EL `N8N_Client` DEBERÁ reintentar hasta 2 veces con backoff exponencial de 1s y 2s antes de registrar el fallo.
5. IF `N8N_ENABLED` es `false` o la URL del webhook está vacía, THEN EL `N8N_Client` DEBERÁ retornar `False` sin lanzar excepción y registrar el motivo en DEBUG.
6. EL `N8N_Client` DEBERÁ sanitizar el payload para que no contenga valores `NaN`, `Inf`, ni objetos no serializables en JSON antes de enviar.

---

### Requisito 6 — Mejora del Realtime Monitor: Detección de Comportamiento vs. Solo Telemetría

**User Story:** Como analista de seguridad, quiero que el endpoint `/scan/realtime` diferencie claramente entre monitorización de sistema y detección de comportamiento malicioso, para no confundir métricas de rendimiento con indicadores de compromiso.

#### Criterios de Aceptación

1. EL `Realtime_Service` DEBERÁ invocar `BehavioralShield.analyze_process(pid)` para cada proceso listado y agregar `behavioral_risk_score`, `behavioral_is_suspicious` y `suspicious_actions` al objeto de proceso retornado.
2. EL `Realtime_Service` DEBERÁ diferenciar en la respuesta API entre `risk_level = "suspicious"` por CPU/memoria alta (monitorización de rendimiento) y `risk_level = "suspicious"` por indicadores de comportamiento malicioso (detección de malware), añadiendo el campo `risk_reason: "performance" | "behavioral"`.
3. MIENTRAS se ejecute el análisis de todos los procesos, EL `Realtime_Service` DEBERÁ aplicar un timeout global de 10 segundos y retornar los resultados parciales obtenidos hasta ese momento.
4. IF un proceso lanza `psutil.AccessDenied` durante el análisis, THEN EL `Realtime_Service` DEBERÁ incluirlo en la respuesta con `risk_level = "unknown"` y `access_denied = true` en lugar de omitirlo.
5. EL `Realtime_Service` DEBERÁ limitar el análisis behavioral detallado a los top-20 procesos por CPU para evitar sobrecarga del sistema.

---

### Requisito 7 — Robustez del Pipeline ante Fallos de Capas Críticas

**User Story:** Como ingeniero de seguridad, quiero que el pipeline nunca clasifique un archivo como CLEAN cuando una capa crítica de análisis falla, para evitar el escenario `Error → CLEAN` que permite evasión por fallo inducido.

#### Criterios de Aceptación

1. IF el modelo ONNX no está cargado o lanza una excepción durante inferencia, THEN EL Engine DEBERÁ establecer `label = "UNKNOWN"`, `score = -1.0`, `operational_status = "SUSPICIOUS"` y continuar con las fases heurísticas restantes.
2. IF el Extractor entra en modo `RAW_FALLBACK`, THEN EL Engine DEBERÁ registrar `extraction_mode = "RAW_FALLBACK"` en `details.diagnostics` y establecer `confidence = "Low"` en el resultado final.
3. IF pefile falla completamente (NonPEFileError) Y el archivo tiene extensión `.exe`, `.dll` o `.sys`, THEN EL Engine DEBERÁ establecer `operational_status = "SUSPICIOUS"` en lugar de `NOT_PE`.
4. CUANDO cualquier fase del pipeline lanza una excepción no capturada, EL Engine DEBERÁ capturarla, registrarla en logs con nivel ERROR, continuar con las fases siguientes y agregar `{phase_name}_error: true` al campo `details`.
5. EL Engine DEBERÁ implementar un watchdog de timeout por archivo: IF el análisis completo supera 60 segundos, THEN EL Engine DEBERÁ interrumpir las fases restantes, establecer `operational_status = "SUSPICIOUS"` con `reason = "analysis_timeout"` y retornar el resultado parcial.
6. PARA TODO resultado donde `label == "UNKNOWN"` o `score == -1.0`, EL `Scan_Service` DEBERÁ clasificar como `result = "suspicious"` y `risk_level = "medium"` en lugar de `"benign"`.

---

### Requisito 8 — Seguridad del Backend: Protección ante Archivos Hostiles

**User Story:** Como DevSecOps, quiero que el backend trate todo archivo subido como entrada hostil potencial, para proteger el sistema de path traversal, zip bombs, archivos de nombre malicioso y agotamiento de recursos.

#### Criterios de Aceptación

1. EL Backend DEBERÁ rechazar archivos con extensiones dobles sospechosas (e.g., `.pdf.exe`, `.jpg.dll`) con HTTP 400 y mensaje descriptivo, ANTES de guardar el archivo temporal.
2. EL Backend DEBERÁ verificar que el archivo temporal no supere `MAX_UPLOAD_BYTES` ANTES de escribirlo en disco, usando lectura en streaming con límite, en lugar de `await file.read()` completo en memoria.
3. EL `Scan_Service` DEBERÁ calcular el SHA-256 del archivo en disco ANTES de pasarlo al Engine, usando lectura en chunks de 64 KB para evitar OOM en archivos grandes.
4. IF el directorio temporal `shadownet_uploads` contiene más de 100 archivos (cleanup fallido de llamadas anteriores), THEN EL Backend DEBERÁ ejecutar limpieza de archivos con más de 1 hora de antigüedad antes de guardar el nuevo archivo.
5. EL Backend DEBERÁ implementar rate limiting por `user_id`: máximo 20 escaneos por minuto por usuario, retornando HTTP 429 al exceder el límite.
6. PARA TODO archivo temporal creado durante un escaneo, EL Backend DEBERÁ garantizar su eliminación en el bloque `finally`, incluso si el escaneo falla con excepción no capturada.
7. IF el nombre de archivo subido contiene caracteres de control (ASCII < 0x20) o secuencias Unicode de dirección de texto (RLO/LRO), THEN EL Backend DEBERÁ sanitizarlo antes de guardarlo, eliminando esos caracteres.

---

### Requisito 9 — Suite de Tests: Cobertura de Detección y Seguridad

**User Story:** Como QA Engineer, quiero una suite de tests que valide el comportamiento real del pipeline de detección, para poder verificar que las mejoras no introducen regresiones y que las capas de seguridad funcionan correctamente.

#### Criterios de Aceptación

1. EL Proyecto DEBERÁ contener tests unitarios para `PEFeatureExtractor.extract()` que verifiquen: (a) archivo PE normal produce vector de dimensión 2381, (b) archivo no-PE lanza `NonPEFileError`, (c) archivo vacío lanza `NonPEFileError`, (d) modo RAW_FALLBACK produce vector no-cero para las features de byte histogram.
2. EL Proyecto DEBERÁ contener tests unitarios para `ShadowNetEngine.scan_file()` que verifiquen: (a) YARA match retorna inmediatamente con `label = "MALWARE"`, (b) ONNX falla → `label = "UNKNOWN"` y `operational_status = "SUSPICIOUS"`, (c) archivo no-PE con extensión `.exe` retorna `operational_status = "SUSPICIOUS"`.
3. EL Proyecto DEBERÁ contener tests de integración para el pipeline end-to-end que utilicen el dataset `data/test_set/` (X_test.npy, y_test.npy) y verifiquen que la accuracy no baje del umbral establecido en configuración.
4. EL Proyecto DEBERÁ contener tests de seguridad para el Backend que verifiquen: (a) path traversal en nombre de archivo es sanitizado, (b) archivo mayor a MAX_UPLOAD_BYTES retorna HTTP 413, (c) request sin JWT retorna HTTP 401, (d) JWT expirado retorna HTTP 401.
5. EL Proyecto DEBERÁ contener tests para `Quarantine_Manager` que verifiquen: (a) archivo normal es cuarentenado correctamente y SHA-256 coincide con metadata, (b) symlink es rechazado con `SYMLINK_REJECTED`, (c) path traversal en destino es rechazado con `PATH_TRAVERSAL_REJECTED`, (d) restauración verifica integridad SHA-256.
6. EL Proyecto DEBERÁ contener una propiedad de round-trip para la serialización del `ScanResult`: serializar a dict → deserializar desde dict → serializar de nuevo → los dos dicts son equivalentes.
7. EL Proyecto DEBERÁ contener tests para el modo de degradación del pipeline: IF se mockea ONNX para lanzar RuntimeError, THEN `scan_file()` DEBERÁ retornar resultado con `operational_status != "CLEAN"`.

---

### Requisito 10 — Persistencia de Configuración: Settings Extendido

**User Story:** Como operador de despliegue, quiero que todas las constantes críticas del sistema sean configurables vía variables de entorno con valores por defecto seguros, para poder adaptar el sistema a diferentes entornos sin modificar código.

#### Criterios de Aceptación

1. EL `Settings` DEBERÁ exponer las siguientes configuraciones vía variables de entorno con los valores por defecto indicados: `QUARANTINE_DIR` (default: `~/.shadownet/quarantine`), `ANALYSIS_TIMEOUT_SECONDS` (default: `60`), `BEHAVIORAL_SHIELD_TIMEOUT_SECONDS` (default: `2`), `MAX_UPLOAD_MB` (default: `50`), `RATE_LIMIT_SCANS_PER_MINUTE` (default: `20`).
2. EL `Settings` DEBERÁ validar en startup que `MODEL_PATH` y `SCALER_PATH` existen en disco, y registrar WARNING en logs si no existen.
3. EL `Settings` DEBERÁ exponer `SUPABASE_INCIDENTS_TABLE` (default: `"incidents"`) para hacer configurable el nombre de la tabla de incidentes.
4. CUANDO se inicie el backend, EL `Settings` DEBERÁ registrar en INFO todos los valores de configuración activos, EXCEPTO las claves secretas (`SUPABASE_KEY`, `SUPABASE_JWT_SECRET`), que DEBERÁN ser enmascaradas con `***`.

---

### Requisito 11 — Endpoint de Salud Extendido con Estado del Pipeline

**User Story:** Como DevOps, quiero que el endpoint `/health` reporte el estado real de cada componente del pipeline, para detectar degradaciones antes de que afecten al usuario.

#### Criterios de Aceptación

1. EL endpoint `GET /health` DEBERÁ retornar el estado de cada componente: `onnx_model` (loaded/missing), `yara_scanner` (available/unavailable), `supabase` (connected/disconnected/not_configured), `n8n` (enabled/disabled), `psutil` (available/unavailable), `offline_queue_size` (int).
2. IF algún componente crítico (`onnx_model`, `yara_scanner`) está en estado degradado, THEN EL endpoint `GET /health` DEBERÁ retornar HTTP 503 en lugar de HTTP 200.
3. EL endpoint `GET /health` DEBERÁ incluir el campo `pipeline_mode`: `full` (todos los componentes activos), `degraded` (uno o más componentes faltantes), `minimal` (solo extractor activo).
4. EL endpoint `GET /health` DEBERÁ ser accesible SIN autenticación JWT para permitir healthchecks de infraestructura.

---

### Requisito 12 — Despliegue: Script de Servicio Windows y Linux

**User Story:** Como ingeniero de sistemas, quiero scripts de instalación como servicio para Windows (Task Scheduler / NSSM) y Linux (systemd), para poder desplegar ShadowNet Defender como servicio persistente en endpoints reales.

#### Criterios de Aceptación

1. EL Proyecto DEBERÁ incluir un archivo `deploy/shadownet.service` con una unit file systemd válida que inicie el backend FastAPI con `uvicorn`, configurando `Restart=on-failure`, `RestartSec=5s`, `WorkingDirectory` y carga de variables desde `.env`.
2. EL Proyecto DEBERÁ incluir un script `deploy/install_linux.sh` que: verifique Python >= 3.10, instale dependencias desde `requirements.txt`, copie la unit file a `/etc/systemd/system/`, ejecute `systemctl enable` y `systemctl start`.
3. EL Proyecto DEBERÁ incluir un script `deploy/install_windows.ps1` que: verifique Python >= 3.10, instale dependencias, registre el backend como servicio usando `NSSM` o `sc.exe`, y configure inicio automático.
4. EL `deploy/install_linux.sh` DEBERÁ verificar que el usuario de ejecución NO es root, y si lo es, DEBERÁ crear un usuario dedicado `shadownet` sin privilegios de login para ejecutar el servicio.
5. CUANDO el servicio inicie, DEBERÁ verificar la existencia del modelo ONNX y del scaler, y si no existen, DEBERÁ terminar con código de salida 1 y mensaje de error claro en los logs del servicio.

