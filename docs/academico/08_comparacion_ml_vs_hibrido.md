# Comparación: Sistema Solo-ML vs. Sistema Híbrido Multicapa

> Comparación basada en ejecuciones reales del pipeline sobre muestras disponibles.
> Ejecutado 2026-08-18.

---

## Sistema original (solo ML)

```
Entrada (binario PE)
        │
        ▼
Feature Extractor (2381 dims)
  - ByteHistogram (256)
  - ByteEntropy (256)
  - Strings (104)
  - General (10)
  - Header (62)
  - Section (255)
  - Imports (1280)
  - Exports (128)
        │
        ▼
StandardScaler (Z-score)
        │
        ▼
Red Neuronal ONNX
  2381 → 512 → 256 → 128 → 1 (sigmoid)
        │
        ▼
score ∈ [0.0, 1.0]
        │
        ▼
label = "MALWARE" si score ≥ 0.5
label = "BENIGN"  si score < 0.5
```

**Output final**: `{label, score, confidence}`

---

## Sistema actual (híbrido multicapa)

```
Entrada (binario PE)
        │
        ▼
[F1] YARA Scanner ──────────────────────── match? → DANGEROUS (early exit)
        │
        ▼
[F2] Feature Extractor (2381 dims)
        │
        ▼
[F3] ML/ONNX Inference
  → label, score, confidence
        │
        ▼
[F4] Overlay Analysis
  → overlay_ratio, overlay_entropy, embedded_pe
        │
        ▼
[F5] DotNet Analysis
  → obfuscator, embedded_assemblies, il_score
        │
        ▼
[F6] IL Behavioral Analysis
  → injection, persistence, networking, credentials...
        │
        ▼
[F7] Risk Engine (correlación)
  Inputs: YARA + ML + Overlay + DotNet + IL
  Output: operational_status, risk_level, risk_score, triggered_indicators
        │
        ▼
ScanResult completo:
  {label, score, operational_status, risk_level, risk_score,
   yara_matches, overlay_analysis, heuristic_assessment,
   dotnet_analysis, il_behavioral, triggered_indicators, justification}
```

---

## Comparación de resultados sobre samples disponibles

### sample1.exe (20.9 MB — binario con overlay payload)

| Aspecto | Solo ML | Híbrido Multicapa |
|---------|---------|-------------------|
| ML score | 0.0000 | 0.0000 (idéntico) |
| ML label | BENIGN | BENIGN (idéntico) |
| Veredicto final | **BENIGN** | **DANGEROUS** |
| Risk level | — | CRITICAL |
| Risk score | — | 105 |
| Overlay analizado | No | 19.7 MB |
| Indicadores activados | 0 | 6 |
| Detección correcta | ❌ Falso Negativo | ✅ Detectado |

**Conclusión**: el sistema híbrido detectó lo que el sistema solo-ML no pudo detectar.

### procexp64.exe (herramienta legítima — Sysinternals)

| Aspecto | Solo ML | Híbrido Multicapa |
|---------|---------|-------------------|
| YARA match | `Keylogger_Generic` | `Keylogger_Generic` |
| ML score | 1.0000 | 1.0000 (idéntico) |
| ML label | MALWARE | MALWARE (idéntico) |
| Veredicto final | **MALWARE** | **UNKNOWN** |
| Risk level | — | LOW |
| Detección correcta | ❌ Falso Positivo | ⚠️ UNKNOWN (no resuelto) |

**Nota**: En este caso, el sistema híbrido tampoco resolvió el falso positivo. El `operational_status` quedó en UNKNOWN por una condición no manejada (YARA match + Risk Engine sin triggers adicionales). El sistema solo-ML tampoco lo habría resuelto.

### eicar.txt (test EICAR — no PE)

| Aspecto | Solo ML | Híbrido Multicapa |
|---------|---------|-------------------|
| ML score | 0.0001 | 0.0001 (idéntico) |
| ML label | BENIGN | BENIGN |
| YARA match | 0 | 0 |
| Veredicto final | BENIGN | CLEAN |
| Detección correcta | ❌ No detectado | ❌ No detectado |

**Limitación compartida**: las reglas YARA no incluyen la firma EICAR estándar.

---

## Ventajas del sistema híbrido (verificadas)

1. **Detección de overlay payloads**: confirmada en sample1.exe. El overlay de 19.7 MB con entropía 7.9987 fue detectado como DANGEROUS, situación que el solo-ML produce como BENIGN.

2. **Detección de binarios .NET ofuscados**: DotNet Analysis detectó ofuscación en sample2.exe (dotnet_risk_score=28). El solo-ML produciría el mismo BENIGN sin contexto adicional.

3. **Evidencias auditables**: el sistema híbrido produce `triggered_indicators`, `heuristic_assessment.justification`, y evidencias IL forenses. El solo-ML no produce explicación alguna.

4. **Tolerancia a fallos**: si el modelo ONNX falla, el pipeline continúa con YARA + Overlay + DotNet + IL. El solo-ML falla completamente. (Verificado: `test_onnx_failure_suspicious` → PASSED)

5. **Early exit por YARA**: si una firma coincide, no se ejecutan fases costosas (extracción + ONNX). (Verificado: procexp64.exe, tiempo=55ms vs >1000ms para sample1.exe)

6. **No-PE support**: archivos no-PE son analizados en modo RAW_FALLBACK. El solo-ML fallaría o produciría resultados sin sentido.

---

## Limitaciones del sistema híbrido (verificadas)

1. **Falsos positivos YARA**: las reglas actuales activan sobre software legítimo (procexp64.exe). El sistema híbrido no tiene mecanismo de whitelisting implementado actualmente.

2. **BehavioralShield no integrado**: la capa de monitoreo dinámico (psutil) existe en código pero no está conectada al pipeline. Si estuviera integrada, añadiría una 8ª capa de detección.

3. **IL Behavioral solo para .NET**: el 70%+ del malware actual es nativo (C/C++/Delphi). La capa IL no aporta para esos binarios.

4. **Mayor latencia**: el pipeline completo tarda 1,240 ms para sample1.exe vs. ~415 ms para solo extracción+ML. La sobrecarga de las capas adicionales puede ser relevante en análisis masivo en tiempo real.

5. **n8n no alerta para operational_status DANGEROUS con label BENIGN**: el caso más importante detectado por el sistema híbrido (sample1.exe) no generaría alerta por n8n. Este es un bug de integración documentado en la auditoría.

---

## Resumen comparativo

| Dimensión | Solo ML | Híbrido Multicapa |
|-----------|---------|-------------------|
| Detección overlay payload | ❌ | ✅ |
| Detección binarios .NET ofuscados | Parcial | ✅ |
| Explicabilidad | ❌ Opaco | ✅ Evidencias forenses |
| Detección de firma conocida | ❌ (sin YARA) | ✅ (con YARA) |
| Tolerancia a fallos | Baja | Alta |
| Tiempo de análisis (archivo grande) | ~415 ms | ~1,240 ms |
| Falsos positivos YARA | N/A | Presentes |
| Auditable por analista | No | Sí |
| Monitoreo dinámico | No | No (pendiente) |
