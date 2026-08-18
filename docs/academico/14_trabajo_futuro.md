# Trabajo Futuro

> Propuestas derivadas de las limitaciones identificadas en la auditoría.
> Ordenadas por impacto esperado y viabilidad técnica.

---

## TF-01 — Integración de BehavioralShield (monitoreo de procesos)

**Estado actual**: `core/dynamic/process_monitor.py` existe con implementación base usando `psutil`, pero no está conectado a `scan_file()`.

**Trabajo propuesto**:
- Conectar `BehavioralShield` como Fase 8 del pipeline en `core/engine.py`.
- Ejecutar el análisis de comportamiento sobre el PID del proceso si el archivo fue lanzado.
- Detectar indicadores en tiempo real: inyección de código (handle a procesos externos), persistencia (escritura a registry Run), networking anómalo (conexiones a IPs fuera de whitelist).
- Añadir `behavioral_analysis` al `ScanResult` con las mismas estructuras de evidencias que IL Behavioral.

**Impacto esperado**: Cierra el gap entre análisis estático y detección de comportamiento. Permite detectar malware que es benigno en análisis estático pero malicioso en ejecución (CE-05).

---

## TF-02 — Detección de malware en memoria (memory forensics)

**Estado actual**: No implementado.

**Trabajo propuesto**:
- Integración con Volatility o similar para análisis de volcados de memoria.
- Detección de procesos ocultos (DKOM), hooks en SSDT, inyección de código en procesos benignos.
- Análisis de PE cargados en memoria con estructuras anómalas (reflective loading).
- API: `engine.scan_memory_region(pid, base_address, size)`.

**Impacto esperado**: Detecta malware fileless y técnicas de inyección avanzadas que no dejan artefactos en disco.

---

## TF-03 — Módulo EDR (Endpoint Detection and Response)

**Estado actual**: No implementado. Existe infraestructura de remediación (terminación de procesos) y cuarentena.

**Trabajo propuesto**:
- Integrar BehavioralShield + remediación en un bucle de respuesta continua.
- Políticas configurables: auto-terminate, auto-quarantine, alert-only.
- Dashboard de incidentes activos.
- Integración con SIEM (Supabase ya provee la capa de persistencia; n8n la capa de alertas).
- API: `edr.start_monitoring(paths, policy)`.

**Impacto esperado**: Convierte el sistema de análisis reactivo (análisis a pedido) en un sistema de protección continua.

---

## TF-04 — Sandbox integrado

**Estado actual**: No implementado.

**Trabajo propuesto**:
- Integración con Cuckoo Sandbox o análisis en VM aislada.
- Ejecutar el binario analizado y capturar: system calls, network traffic, file system changes, registry modifications.
- Correlacionar resultados del sandbox con el análisis estático multicapa.
- Calcular métricas de comportamiento observado vs. predicho por IL Behavioral.

**Impacto esperado**: Permite validar experimentalmente los hallazgos del análisis estático y detectar malware con evasión estática avanzada.

---

## TF-05 — Telemetría avanzada y conjunto de evaluación real

**Estado actual**: El test set disponible es sintético. No hay métricas de campo verificadas.

**Trabajo propuesto**:
- Construir un corpus de evaluación real con ground truth externo (VirusTotal, análisis forense).
- Mínimo: 1000 malware + 1000 benignos de campo, con confirmación de al menos 5 motores AV.
- Recalcular el scaler sobre el corpus de campo.
- Calcular y reportar: Accuracy, Precision, Recall, F1, AUC-ROC, FPR@TPR=90%, TPR@FPR=1%.
- Comparar métricas del sistema solo-ML vs. sistema multicapa sobre el corpus real.

**Impacto científico**: Sin este trabajo, las métricas del sistema no pueden ser reportadas con rigor en un artículo revisado por pares.

---

## TF-06 — Soporte Linux (análisis de ELF)

**Estado actual**: El extractor y el pipeline están diseñados para PE (Windows). Los scripts de instalación incluyen `install_linux.sh` para el backend, pero el análisis de binarios es exclusivamente PE.

**Trabajo propuesto**:
- Extractor de features para ELF (Executable and Linkable Format).
- Análisis de secciones ELF, dynamic symbols, RPATH, PT_INTERP.
- Detección de packers Linux (UPX para Linux, custom packers).
- Reglas YARA para malware Linux (rootkits, backdoors, cryptominers).

---

## TF-07 — Soporte Windows completo como servicio

**Estado actual**: `deploy/shadownet.service` y `install_windows.ps1` existen pero el despliegue real como servicio no está documentado como funcional.

**Trabajo propuesto**:
- Despliegue como servicio Windows (Windows Service o NSSM).
- Integración con Windows Event Log para auditoría.
- Protección del proceso del servicio contra terminación por malware (process protection, anti-tampering).
- UI de configuración.

---

## TF-08 — Generación automática de reglas YARA

**Estado actual**: 4 archivos de reglas YARA cargados manualmente.

**Trabajo propuesto**:
- Pipeline de generación de reglas YARA a partir de clusters de malware similares.
- Proceso de validación automática contra corpus benigno para controlar FPR.
- Actualización periódica de reglas sin reinicio del servicio.

---

## TF-09 — Interpretabilidad del modelo ML (SHAP)

**Estado actual**: Modelo neuronal opaco.

**Trabajo propuesto**:
- Implementar SHAP (SHapley Additive exPlanations) para el modelo ONNX.
- Identificar las features más influyentes para cada predicción.
- Integrar los valores SHAP en el `ScanResult` y en la explicación LLM.
- Comparar features relevantes entre familias de malware.

**Impacto científico**: Añade interpretabilidad al 4° nivel del sistema (ML), completando la cadena de explicabilidad para todos los componentes.

---

## TF-10 — Corrección de bugs documentados en la auditoría

Los siguientes bugs son de resolución inmediata antes de cualquier trabajo futuro a largo plazo:

| ID | Bug | Prioridad |
|----|-----|-----------|
| B-01 | n8n no alerta para `operational_status=DANGEROUS` con `label=BENIGN` | P0 |
| B-02 | JWT expirado produce HTTP 500 en lugar de 401 | P1 |
| B-03 | `operational_status=UNKNOWN` no manejado por Risk Engine | P1 |
| B-04 | Test set sintético pasa como test de accuracy | P2 |
