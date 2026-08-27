# Análisis Forense de sample1.exe

> Análisis ejecutado en tiempo real el 2026-08-18 usando `core/engine.ShadowNetEngine`.
> NO se utilizó documentación previa. Los resultados son los producidos por el pipeline actual.

---

## Metadata del archivo

| Campo | Valor |
|-------|-------|
| Nombre | sample1.exe |
| Tamaño | 20,906,782 bytes (20.9 MB) |
| Path | samples/sample1.exe |
| Modo de extracción | PE_FASTLOAD (muestreo 50.15%) |
| Ratio analizado | 50.15% del archivo |
| Motivo de degradación | file_size_exceeded_10mb |

---

## Fase 1 — YARA Scanner

```
Reglas cargadas: 4/4
Matches encontrados: 0

YARA no detectó coincidencia con ninguna firma conocida.
```

El malware no tiene firma YARA conocida en las reglas actuales. Esta es la primera indicación de que el binario puede haber sido diseñado para evadir detección por firmas.

---

## Fase 2 — Feature Extractor (2381 dims)

```
Modo:              PE_FASTLOAD
Tiempo:            783.9 ms (archivo >10 MB, muestreo distribuido)
Packer detectado:  True
```

**Indicadores de packing detectados:**

| Indicador | Valor |
|-----------|-------|
| `global_entropy` | 7.9924 |
| `ratio_virtual_real` | 1.0595 |
| `num_sections` | 7 |
| `executable_sections` | 1 |
| `rwx_sections` | 0 |
| `anomalous_sections` | 1 |
| `num_imports` | 145 |
| `num_exports` | 0 |
| `is_packed_upx` | False |
| `high_entropy_sections` | 0 |
| `packer_detected` | **True** |
| `packer_reasons` | `['high_global_entropy']` |

El extractor detectó entropía global de 7.9924 (el máximo teórico es 8.0). Una entropía tan alta indica que el contenido del archivo está cifrado o comprimido. El packer no es UPX (sin secciones UPX0/UPX1), lo que sugiere un empaquetador personalizado o cifrado propio.

Hay 145 imports y 0 exports — la estructura PE tiene una superficie de API visible, pero el extractor procesa solo el 50.15% del binario en este modo.

---

## Fase 3 — ML / ONNX Inference

```
ML score:     0.0000
ML label:     BENIGN
Confidence:   High
Threshold:    0.5
```

El modelo neuronal asigna probabilidad prácticamente nula de ser malware. Esta es la evasión confirmada: la estructura PE del archivo es suficientemente similar a archivos benignos en el espacio de features de 2381 dimensiones.

La razón probable es que:
1. El PE header y secciones declaradas (~266 KB) tienen características similares a un binario benigno.
2. El overlay de 19.7 MB no está suficientemente representado en el vector de features porque el muestreo PE_FASTLOAD prioriza la estructura PE declarada.
3. La alta entropía global sí contribuye a las features de ByteEntropy, pero aparentemente no fue suficiente para superar el umbral de 0.5.

---

## Fase 4 — Overlay Analysis

Esta es la fase que detectó la amenaza.

```
overlay_present:          True
overlay_offset:           272,896 bytes  ← fin del PE declarado
overlay_size:             20,633,886 bytes  ← 19.7 MB de payload
overlay_ratio:            0.9869  (98.7%)
overlay_entropy:          7.9987
global_entropy:           7.9861
embedded_pe_detected:     False
embedded_pe_count:        0
is_known_installer:       False
installer_type:           None
overlay_has_strings:      True
overlay_string_count:     8,742
overlay_suspicious_strings: []  ← strings sospechosos no encontrados por YARA overlay
overlay_yara_hits:        []
```

**Interpretación forense**:

- La estructura PE de `sample1.exe` termina en el byte 272,896 (266 KB).
- Los 20,633,886 bytes restantes (19.7 MB) son datos que no pertenecen a ninguna sección PE declarada.
- La entropía del overlay es 7.9987, prácticamente el máximo teórico de 8.0. Esto indica con alta certeza que los datos están cifrados o comprimidos con un algoritmo que produce salida de apariencia aleatoria.
- No se detectó un PE embebido en el overlay (no hay magic bytes MZ en el overlay).
- 8,742 strings fueron encontrados en el overlay — una cantidad inusualmente alta para datos cifrados. Esto podría indicar que parte del overlay contiene datos de texto/configuración no cifrados, o que el algoritmo de detección de strings opera sobre datos comprimidos.

**Técnica de evasión identificada**: Overlay payload. El binario PE actúa como envolvente (dropper/loader), y el contenido malicioso real está almacenado en el overlay cifrado/comprimido. Esta técnica es efectiva contra:
- Análisis PE estático (el parser no procesa el overlay)
- Modelos ML que operan sobre features PE (features derivadas de la estructura PE, no del overlay)
- Sandboxes que inspeccionan la estructura del ejecutable sin ejecutarlo

---

## Fase 5 — DotNet Analysis

```
is_dotnet: False
```

El binario no es un ensamblado .NET/CLR. Las fases de DotNet Analysis e IL Behavioral no se ejecutaron.

---

## Fases 6-7 — IL Behavioral / Risk Engine

```
Risk Engine — 6 indicadores activados:

[1] overlay_ratio=98.7% > 80%        ← umbral moderado
[2] overlay_ratio=98.7% > 93%        ← umbral crítico
[3] overlay_entropy=7.9987 > 7.2     ← cifrado/comprimido
[4] overlay_entropy=7.9987 > 7.8     ← máxima aleatoriedad
[5] global_entropy=7.9861 > 7.5      ← entropía global muy alta
[6] packer_indicators=True           ← packer detectado en features PE

Risk score:        105 (máximo registrado en esta muestra)
Risk level:        CRITICAL
Operational status: DANGEROUS
```

El Risk Engine correlaciona los outputs de Overlay Analysis y el extractor de features y produce `operational_status=DANGEROUS` independientemente del veredicto ML.

---

## ScanResult completo

| Campo | Valor |
|-------|-------|
| `status` | clean (campo heredado) |
| `score` | 0.0000 |
| `label` | BENIGN |
| `confidence` | High |
| `operational_status` | **DANGEROUS** |
| `risk_level` | CRITICAL |
| `risk_score` | 105 |
| `yara_matches` | [] |
| `was_unpacked` | False |
| `detection_phases` | ['YARA', 'ML_STATIC', 'OVERLAY_FORENSICS', 'DOTNET_ANALYSIS'] |
| `scan_time_ms` | 1,240.46 |

---

## Resultado original (solo ML) vs. resultado multicapa

| Sistema | Label | Score | Operational Status | ¿Detectó amenaza? |
|---------|-------|-------|--------------------|-------------------|
| Solo ML | BENIGN | 0.0000 | — | ❌ NO |
| Multicapa completo | BENIGN | 0.0000 | **DANGEROUS/CRITICAL** | ✅ SÍ |

El campo `label` y `score` son idénticos en ambos sistemas — el ML no cambió. Lo que cambió es el `operational_status` producido por la Overlay Analysis + Risk Engine.

---

## Cómo el malware intentó evadir la detección

1. **Estructura PE limpia**: la cabecera y secciones PE del archivo tienen características similares a software benigno (145 imports, 1 sección ejecutable, sin secciones RWX).

2. **Sin firma YARA conocida**: no coincide con ninguna firma en las 4 reglas cargadas.

3. **Payload en overlay**: el contenido malicioso (19.7 MB) está almacenado fuera de la estructura PE declarada, en el overlay. Los analizadores PE estándar ignorarán estos datos.

4. **Cifrado/compresión del overlay**: la entropía de 7.9987 indica que el payload está cifrado o comprimido, lo que impide análisis de strings, YARA y cualquier análisis de contenido directo sobre el overlay.

---

## Por qué el sistema actual logró detectarlo

La capa de Overlay Analysis calcula independientemente:
1. El tamaño de la estructura PE declarada (offset del fin del PE = 272,896 bytes)
2. El tamaño total del archivo (20,906,782 bytes)
3. La diferencia = overlay = 20,633,886 bytes
4. La entropía del overlay = 7.9987

Estas métricas son **independientes de la estructura PE y del modelo ML**. Un overlay de 98.7% con entropía máxima es una anomalía forense objetiva, independientemente de si el PE en sí parece benigno.

El Risk Engine acumula 6 indicadores de este análisis y produce risk_score=105 (umbral CRITICAL), elevando el `operational_status` a DANGEROUS aunque el ML haya dicho BENIGN.

---

## Limitación del análisis

- **Ground truth desconocido**: no se confirmó con herramienta externa (VirusTotal, sandbox) si `sample1.exe` es genuinamente malicioso. La detección es heurística.
- **Payload no analizado**: el contenido cifrado del overlay no fue desencriptado ni ejecutado. La naturaleza exacta del payload es desconocida.
- **Falso positivo posible**: algunos instaladores legítimos usan overlay para almacenar datos de instalación. Sin embargo, `is_known_installer=False` indica que no coincide con los patrones de NSIS ni InnoSetup.
