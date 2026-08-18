# Hallazgos — Numerados y con Evidencia

> Solo se documentan hallazgos derivados de código real, ejecuciones reales
> y tests verificados. Fecha de auditoría: 2026-08-18.

---

## H-01 — Divergencia ML vs. Heurística en presencia de overlay payload

**Evidencia**: Ejecución real de `engine.scan_file('samples/sample1.exe')`, 2026-08-18.

```
ML score:          0.0000 → BENIGN (confianza: High)
Overlay ratio:     98.7%
Overlay entropy:   7.9987
Risk score:        105 (CRITICAL)
Operational status: DANGEROUS
```

**Descripción**: El modelo neuronal (2381 features, SOREL-20M) asignó probabilidad prácticamente nula de malware a un binario donde el 98.7% de su contenido (19.7 MB) es un overlay con entropía máxima (7.9987). La capa de Overlay Analysis detectó correctamente la anomalía y el Risk Engine elevó el `operational_status` a DANGEROUS con 6 indicadores activados.

**Impacto**: Un sistema que solo usara ML hubiera producido un falso negativo. El sistema multicapa detectó la amenaza mediante una capa analítica independiente.

**Relevancia científica**: Demuestra empíricamente que las técnicas de overlay payload constituyen un vector de evasión efectivo contra ML estático sobre features PE. La solución no es mejorar el modelo ML, sino añadir capas de análisis ortogonales.

---

## H-02 — Test set sintético incompatible con el scaler de producción

**Evidencia**: Análisis directo de `data/test_set/X_test.npy` y `models/scaler.pkl`, 2026-08-18.

```python
# Post-scaling statistics:
mean  = 21.73  (expected: ~0)
std   = 112.1  (expected: ~1)
AUC-ROC con scaler = 0.50 (equivalente a aleatorio)
AUC-ROC sin scaler, etiquetas invertidas = 1.00 (sintético perfectamente separable)
```

**Descripción**: El archivo `data/test_set/X_test.npy` contiene 1000 muestras con features en rango [0, 1] que no son compatibles con el `scaler.pkl` de producción. Al aplicar el scaler, las features se distorsionan severamente. El test set es sintético y perfectamente separable (AUC=1.0) — diseñado para validar el pipeline de integración, no para medir rendimiento estadístico del modelo.

**Impacto**: No es posible reportar métricas de accuracy, FPR, FNR del modelo ML a partir de los artefactos disponibles en el repositorio.

**Relevancia científica**: Revela una deuda técnica importante: el proyecto carece de un conjunto de evaluación real y representativo para el modelo ML.

---

## H-03 — Falso positivo YARA en software legítimo (Sysinternals)

**Evidencia**: Ejecución real de `engine.scan_file('samples/procexp64.exe')`, 2026-08-18.

```
Archivo:       procexp64.exe (Process Explorer, Sysinternals/Microsoft)
YARA match:    Keylogger_Generic (categoría: spyware)
ML score:      1.0000
ML label:      MALWARE
Operational:   UNKNOWN
```

**Descripción**: Process Explorer, una herramienta legítima de monitoreo del sistema de Microsoft, activa la regla YARA `Keylogger_Generic`. El modelo ML también produce score=1.0 (MALWARE) para este archivo. El `operational_status` quedó en UNKNOWN — una condición no manejada por el Risk Engine.

**Impacto**: La tasa de falsos positivos de las reglas YARA actuales no es despreciable. Herramientas de administración de sistemas, debuggers y profilers comparten API y patrones de comportamiento con malware de monitoreo.

**Relevancia científica**: Evidencia la necesidad de un mecanismo de whitelisting o ajuste de reglas YARA para reducir FPR en entornos de administración. También revela un estado no manejado (`UNKNOWN`) en el Risk Engine.

---

## H-04 — BehavioralShield implementado pero no integrado al pipeline

**Evidencia**: Revisión directa de `core/dynamic/process_monitor.py` y `core/engine.py`, 2026-08-18.

El código de monitoreo dinámico de procesos (psutil) existe y compila, pero no está conectado a `scan_file()`. El pipeline termina en la fase del Risk Engine sin ejecutar análisis dinámico.

**Impacto**: El sistema actual es completamente estático. No hay detección de comportamiento en tiempo de ejecución. Un malware que sea benigno en análisis estático pero malicioso en ejecución no sería detectado.

**Relevancia científica**: Define claramente el límite del sistema actual (análisis estático + heurístico) y establece la necesidad de integración de monitoreo dinámico como trabajo futuro.

---

## H-05 — n8n no alerta para el caso de detección más crítico

**Evidencia**: Revisión de `backend/app/integrations/` y tests de n8n, 2026-08-18.

```python
# n8n solo envía para:
if result == "malicious":  # label ML
    n8n_client.send()

# NO envía para:
if operational_status == "DANGEROUS" and label == "BENIGN":
    pass  # silencio — el caso más importante del sistema
```

**Descripción**: El cliente n8n está configurado para enviar alertas solo cuando el label ML es "malicious". El caso de `sample1.exe` — donde ML=BENIGN pero operational_status=DANGEROUS — no generaría ninguna alerta.

**Impacto**: El hallazgo científico más importante del sistema (detección de overlay payload que el ML no detectó) no dispara la cadena de alertas automatizadas.

**Relevancia científica**: Demuestra una brecha arquitectónica entre la capa de detección heurística y la capa de respuesta automatizada. El sistema detecta pero no actúa sobre su detección más valiosa.

**Test que verifica el comportamiento actual** (pasa, confirmando el bug por diseño):
```
test_send_scan_result_skips_benign   → PASSED
test_send_scan_result_skips_suspicious → PASSED
test_send_scan_result_sends_malicious  → PASSED
```

---

## H-06 — JWT expirado produce HTTP 500 en lugar de HTTP 401

**Evidencia**: Test `TestExpiredJWT::test_expired_token_rejected` → FAILED, 2026-08-18.

```
Expected: 401 Unauthorized
Received: 500 Internal Server Error
Log: "Ni SUPABASE_URL ni SUPABASE_JWT_SECRET configurados"
```

**Descripción**: Cuando las variables de entorno de Supabase no están configuradas y se recibe un JWT expirado, el handler de autenticación lanza una excepción no capturada que produce HTTP 500. El servidor debería retornar 401 de forma controlada.

**Impacto**: Falla de seguridad menor: expone información sobre el estado de configuración del servidor y no implementa el comportamiento de fail-secure.

**Relevancia científica**: Evidencia que la gestión de errores en el flujo de autenticación no está completamente implementada.

---

## H-07 — La detección de familias de malware .NET funciona sobre datos sintéticos

**Evidencia**: Tests de IL Analyzer, 2026-08-18.

```
test_xworm_family_top        → PASSED
test_agenttesla_family_top   → PASSED
test_threat_score_critical_xworm → PASSED
```

Los tests demuestran que el sistema puede identificar familias de malware (XWorm, AgentTesla) y calcular threat scores correctamente. Sin embargo, los datos de prueba son sintéticos (strings y tokens construidos manualmente), no binarios reales.

**Relevancia científica**: El mecanismo de detección de familias está implementado y es funcionalmente correcto sobre datos sintéticos. La validación sobre binarios .NET maliciosos reales es trabajo pendiente.

---

## H-08 — Análisis en archivos >10 MB: solo 50.15% del binario es analizado

**Evidencia**: Log de ejecución real de sample1.exe, 2026-08-18.

```
modo=PE_FASTLOAD
ratio_analizado=50.2%
degradation_reason=file_size_exceeded_10mb
```

**Descripción**: El extractor usa muestreo distribuido para archivos >10 MB, analizando inicio, centro y fin del archivo para evitar OOM. Para sample1.exe (20.9 MB), solo el 50.15% fue analizado por el extractor de features.

**Impacto**: Un atacante que distribuya features maliciosas específicamente en las regiones no muestreadas podría evadir la capa ML. En este caso, además, el overlay está al final del archivo — que sí es muestreado — pero la entropía del overlay se mezcla con la entropía del PE en el vector de features.

**Relevancia científica**: Define un límite de cobertura del extractor y un vector de evasión teórico para archivos grandes.
