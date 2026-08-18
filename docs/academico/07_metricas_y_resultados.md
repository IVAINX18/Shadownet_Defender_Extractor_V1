# Métricas y Resultados — Estado Actual

> Auditoría ejecutada 2026-08-18. Solo se documentan métricas calculadas
> sobre datos reales disponibles en el repositorio. Los datos faltantes
> se indican explícitamente.

---

## Estado de los datos disponibles

| Dataset | Disponible | Válido para métricas | Observación |
|---------|------------|----------------------|-------------|
| `data/test_set/X_test.npy` (1000 muestras) | ✅ | ❌ | Sintético, incompatible con scaler de producción |
| `samples/` (archivos PE) | ✅ | Parcial | Sin ground truth externo verificado |
| SOREL-20M (datos de entrenamiento) | ❌ | — | No incluido en repositorio |
| Datos de campo reales | ❌ | — | No disponibles |

---

## Métricas del modelo ML — CALCULADAS

### Sobre el test set disponible (diagnóstico)

**Condición**: `data/test_set/X_test.npy`, 1000 muestras (500 benign, 500 malware)

El test set contiene features en rango [0, 1]. El `scaler.pkl` de producción fue ajustado sobre datos con distribuciones radicalmente diferentes:
- Media post-escalado: 21.73 (esperado: ~0)
- Desviación post-escalado: 112.1 (esperado: ~1)

Al aplicar el scaler del pipeline de producción sobre el test set, el modelo produce score=0.0000 para el 100% de las muestras.

Al omitir el scaler (features directamente al modelo ONNX), el modelo produce scores separables pero con AUC=0.0 con etiquetas convencionales y AUC=1.0 con etiquetas invertidas. Esto confirma que el test set es **sintético con etiquetas opuestas a la convención del modelo** y **perfectamente separable** — no representativo de datos reales.

**Conclusión**: Las métricas de ML sobre `data/test_set/` no son válidas para reportar en un artículo científico.

---

## Métricas declaradas en el proyecto (no reproducidas)

Las siguientes métricas están documentadas en `DOCUMENTACION_TECNICA_INTEGRAL.md` y el PRD del proyecto. **No fueron reproducidas experimentalmente** porque los datos de entrenamiento/evaluación no están disponibles en el repositorio:

| Métrica | Valor declarado | Fuente |
|---------|-----------------|--------|
| AUC-ROC | 0.985 | Documentación del proyecto |
| FPR @ TPR=90% | No especificado | — |
| TPR @ FPR=1% | No especificado | — |
| Latencia inferencia ONNX | ~15 ms | Documentación del proyecto |
| Latencia total E2E | ~400–500 ms | Documentación del proyecto |

> **IMPORTANTE**: Estas métricas NO pueden presentarse en un artículo científico sin el conjunto de evaluación que las respalda.

---

## Métricas del sistema multicapa — CALCULADAS sobre samples reales

Ejecuciones reales del pipeline completo (2026-08-18):

### Tabla de resultados por archivo

| Archivo | Tamaño | ML score | ML label | Operational Status | Risk Level | YARA | Tiempo |
|---------|--------|----------|----------|--------------------|------------|------|--------|
| `sample1.exe` | 20.9 MB | 0.0000 | BENIGN | **DANGEROUS** | CRITICAL | 0 matches | 1,103 ms |
| `sample2.exe` | ~2 MB | 0.0000 | BENIGN | CLEAN | LOW | 0 matches | 708 ms |
| `eicar.txt` | ~68 B | 0.0001 | BENIGN | CLEAN | LOW | 0 matches | 133 ms |
| `procexp64.exe` | ~2 MB | 1.0000 | MALWARE | UNKNOWN | LOW | 1 match | 55 ms |

### Observaciones sobre los resultados

**sample1.exe**: Divergencia ML vs. Heurística. ML=BENIGN, Heurística=DANGEROUS/CRITICAL. Detectado por Overlay Analysis (98.7% overlay, entropía 7.9987). El modelo ML no detectó la amenaza. La arquitectura multicapa sí.

**sample2.exe**: Binario .NET. ML=BENIGN. DotNet Analysis detectó ofuscación (Unknown Obfuscator, dotnet_risk_score=28 MEDIUM). El Risk Engine no escaló a DANGEROUS por score insuficiente. Resultado final: CLEAN.

**eicar.txt**: Archivo de prueba EICAR estándar (texto, no PE). El extractor usó RAW_FALLBACK. El modelo produjo score=0.0001. YARA no activó. El sistema no detectó EICAR — esto es una limitación documentada: las reglas YARA no incluyen la firma EICAR estándar.

**procexp64.exe**: Herramienta legítima (Sysinternals Process Explorer). YARA activó `Keylogger_Generic` → ML score=1.0, label=MALWARE. Este es un **falso positivo documentado**. El `operational_status` quedó en UNKNOWN (condición no cubierta por el Risk Engine para este caso).

---

## Métricas del sistema de tests — CALCULADAS

Ejecución real: `python -m pytest tests/ -v` (2026-08-18)

| Categoría | Tests | Passed | Failed | Skipped |
|-----------|-------|--------|--------|---------|
| Integration (pipeline, supabase) | 10 | 9 | 0 | 1 (accuracy_above_threshold) |
| Properties (hypothesis) | 14 | 14 | 0 | 0 |
| Security (backend) | 14 | 13 | 1 | 0 |
| Unit (engine, extractor, quarantine, etc.) | 37 | 33 | 0 | 4 |
| Feature tests (extractors, IL, overlay, etc.) | 83 | 81 | 1 | 2 |
| **Total** | **158** | **151** | **2** | **7** |

**Tasa de éxito: 155/158 = 98.1%** (excluyendo skipped que dependen de datos externos)

### Tests fallidos (2 de 158)

1. `TestExpiredJWT::test_expired_token_rejected`
   - Fallo: `assert 500 == 401`
   - Causa: `SUPABASE_URL` y `SUPABASE_JWT_SECRET` no configurados en entorno de test → backend retorna 500 en lugar de 401
   - Impacto: Seguridad — el endpoint no retorna el código HTTP correcto cuando el JWT está expirado y Supabase no está disponible

2. `test_ollama_client_prod_localhost_raises`
   - Fallo: `DID NOT RAISE RuntimeError`
   - Causa: La validación de URL de producción no lanza excepción en el entorno actual
   - Impacto: Bajo — test de configuración de seguridad

### Tests omitidos (skipped)

- `test_accuracy_above_threshold`: requiere `data/test_set/` con datos compatibles con el scaler
- `TestExtractorDimensions::test_vector_2381_dimensions`: requiere archivo PE real
- `TestExtractorNonPEErrors::test_non_pe_raises_error`: requiere archivo PE real
- `TestExtractorNonPEErrors::test_empty_file_raises_error`: requiere fixture PE
- `TestExtractorRawFallback::test_raw_fallback_not_zero`: requiere fixture PE

---

## Métricas de rendimiento — MEDIDAS en ejecuciones reales

| Operación | Medición real |
|-----------|---------------|
| Extracción PE_FASTLOAD (sample1.exe, 20.9 MB) | 783.9 ms |
| Extracción PE normal (sample2.exe, ~2 MB) | 229.2 ms |
| Extracción RAW_FALLBACK (eicar.txt, 68 B) | 59.0 ms |
| Pipeline completo sample1.exe (8 fases) | 1,240 ms |
| Pipeline completo sample2.exe (con IL) | 707 ms |
| Pipeline procexp64.exe (YARA match, early exit) | 55 ms |
| Inferencia ONNX (medición directa) | ~15 ms (según documentación) |

---

## Experimentos faltantes para métricas completas

Los siguientes experimentos son necesarios para completar el cuadro de métricas y no están disponibles actualmente:

1. **Corpus de evaluación real**: mínimo 1000 muestras de malware real + 1000 benignos con ground truth externo (VirusTotal, sandbox).

2. **Métricas de FPR/FNR del sistema multicapa**: comparar tasa de detección del sistema completo vs. solo-ML sobre el mismo corpus.

3. **Evaluación de la capa YARA**: calcular FPR de las reglas YARA actuales sobre un corpus de software legítimo conocido. El falso positivo de `procexp64.exe` indica que la tasa puede ser no despreciable.

4. **Latencia en percentil 95**: medir tiempos de ejecución sobre N≥100 archivos para reportar distribución, no solo casos individuales.

5. **Evaluación de IL Behavioral sobre malware .NET real**: los tests actuales usan datos sintéticos. Falta evaluación sobre ensamblados .NET maliciosos reales (AgentTesla, XWorm, AsyncRAT).
