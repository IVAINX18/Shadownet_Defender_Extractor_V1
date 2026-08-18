# Modelo ML — SOREL-20M y Arquitectura Neuronal

> Fuente: `models/model_manifest.json`, `models/inference.py`, `extractors/extractor.py`,
> auditoría directa de artefactos en `models/`. Ejecutado 2026-08-18.

---

## Dataset SOREL-20M

SOREL-20M (Sophos/ReversingLabs Open Dataset, 20 Million samples) es uno de los conjuntos de datos de malware más grandes disponibles públicamente. Contiene aproximadamente 20 millones de muestras de archivos PE con metadatos, features pre-extraídas y etiquetas de clasificación binaria (benign/malware).

El modelo de ShadowNet Defender fue entrenado sobre:
- **Dataset base**: SOREL-20M (~5 millones de muestras utilizadas)
- **Dataset propio**: Colección ShadowNet 2024-2026 (~100K muestras adicionales)
- **Total declarado**: ~5.1 millones de muestras de entrenamiento

> NOTA: Los datos de entrenamiento no están incluidos en el repositorio.
> Las métricas de entrenamiento son las declaradas en el manifiesto y documentación del proyecto.
> No fue posible reproducir el proceso de entrenamiento durante esta auditoría.

---

## Vector de 2381 features

El extractor produce un vector de 2381 dimensiones derivado de análisis estático del binario PE:

```
[ByteHistogram: 256] [ByteEntropy: 256] [Strings: 104]
[General: 10] [Header: 62] [Section: 255]
[Imports: 1280] [Exports: 128]
Total: 256+256+104+10+62+255+1280+128 = 2381
```

### Justificación del diseño de features

**ByteHistogram (256)**: Captura la distribución estadística de bytes en el binario. Malware empaquetado/cifrado exhibe distribuciones más uniformes (mayor entropía), mientras que código compilado normal muestra patrones específicos (alta frecuencia de 0x00, 0xFF).

**ByteEntropy (256)**: Complementa el histograma con la entropía de Shannon calculada en ventanas deslizantes. Detecta regiones de alta entropía (código cifrado, overlays comprimidos) que el histograma global puede promediar.

**Strings (104)**: Features derivadas de strings extraídos del binario. Incluye indicadores de comportamiento: URLs, dominios, APIs Windows de riesgo, registry keys de persistencia, comandos de shell.

**Imports (1280)**: Feature hashing de la Import Address Table (IAT). Cada API importada se hashea con SHA-256 y se mapea a un índice mediante módulo 1280. Las APIs de alto riesgo (VirtualAlloc, WriteProcessMemory, CreateRemoteThread) dejan huella estadística consistente entre familias de malware.

---

## Arquitectura neuronal

```
Input layer:   2381 neuronas (vector de features normalizado)
Hidden 1:       512 neuronas + BatchNorm + ReLU + Dropout(p=0.3)
Hidden 2:       256 neuronas + BatchNorm + ReLU + Dropout(p=0.2)
Hidden 3:       128 neuronas + BatchNorm + ReLU + Dropout(p=0.1)
Output:           1 neurona + Sigmoid → score ∈ [0.0, 1.0]
```

**Parámetros de entrenamiento declarados:**
- Framework: PyTorch
- Loss: Binary Cross-Entropy (BCE)
- Optimizer: Adam (lr=0.001)
- Regularización: L2 weight decay (λ=1e-5)
- Exportación: ONNX Opset 11

---

## Preprocesamiento — StandardScaler

Antes de la inferencia, el vector de features se normaliza con Z-score:

```
x_norm[i] = (x[i] - μ[i]) / σ[i]
```

donde `μ` y `σ` fueron calculados sobre las 5.1M muestras de entrenamiento y están almacenados en `models/scaler.pkl` (57 KB, formato joblib).

---

## Artefactos del modelo (verificados)

| Artefecto | Tamaño | SHA-256 (primeros 16 chars) |
|-----------|--------|-----------------------------|
| `best_model.onnx` | 9.3 KB | df832eaceb40043c |
| `best_model.onnx.data` | 5.6 MB | 7482611c343b83cd |
| `scaler.pkl` | 57 KB | b46e743cceccc7dd |

Versión del modelo: `v1.0.1`, creado `2026-02-19`.
Formato: ONNX Runtime. Umbral de producción: 0.5.

---

## Métricas declaradas en el proyecto

Las siguientes métricas están declaradas en la documentación del proyecto (`DOCUMENTACION_TECNICA_INTEGRAL.md` y PRD). **No fueron reproducidas experimentalmente** por incompatibilidad del test set disponible (ver sección Limitaciones):

| Métrica | Valor declarado |
|---------|-----------------|
| AUC-ROC | 0.985 |
| Latencia inferencia ONNX | ~15 ms |
| Latencia total extracción + inferencia | ~400–500 ms |

---

## Hallazgo sobre el test set disponible

Durante la auditoría se identificó que `data/test_set/X_test.npy` **no es compatible** con el `scaler.pkl` de producción:

- `X_test.npy`: 1000 muestras, features en rango [0, 1], dtype float32
- Media post-escalado: **21.73** (esperado: ~0)
- Desviación post-escalado: **112.1** (esperado: ~1)
- AUC-ROC con scaler aplicado: **0.50** (equivalente a aleatorio)

Al aplicar el modelo directamente sobre `X_test` (sin scaler), el modelo produce AUC-ROC = 0.0 con etiquetas convencionales, pero AUC-ROC = 1.0 con etiquetas invertidas, lo que indica que el test set es **sintético y perfectamente separable**.

**Conclusión**: El test set disponible en el repositorio es un conjunto de validación sintético generado para verificar el pipeline de integración, no para medir el rendimiento estadístico real del modelo sobre datos de campo.

Las métricas reales del modelo sobre datos de producción no pueden calcularse a partir de los artefactos disponibles en el repositorio.

---

## ¿Por qué el modelo solo no fue suficiente?

El análisis de `sample1.exe` demuestra el problema central:

```
ML score:           0.0000 → label: BENIGN
Overlay ratio:      98.7% → overlay de 19.7 MB
Overlay entropy:    7.9987 → máxima aleatoriedad (cifrado/comprimido)
Global entropy:     7.9861
Risk score:         105 (CRITICAL)
Operational status: DANGEROUS
```

El modelo ML clasifica `sample1.exe` como benigno con alta confianza (score=0.0000). Sin embargo, el 98.7% del archivo es un overlay con entropía 7.9987 — indicador forense de payload cifrado o comprimido que no pertenece a la estructura PE declarada.

Este escenario corresponde a la técnica de evasión conocida como **overlay payload**: el binario PE es una cáscara pequeña y legítima (o vacía), y el contenido malicioso se almacena en datos adicionales al final del archivo que no son analizados por el parser PE estándar — y por tanto tampoco por las features del extractor.

La capa de Overlay Analysis detecta esto independientemente del modelo ML. Esta es la evidencia empírica del hallazgo principal del proyecto.

---

## Limitaciones identificadas

1. **Test set sintético**: No permite calcular FPR/FNR reales del modelo en campo.
2. **Scaler incompatible**: El `scaler.pkl` de producción no puede aplicarse al test set disponible.
3. **Evasión por muestreo distribuido**: Para archivos >10 MB, el extractor analiza solo el 50.2% del binario. Un atacante puede concentrar código malicioso en las regiones no muestreadas.
4. **Features de imports limitadas**: El feature hashing (módulo 1280) introduce colisiones. APIs con nombres distintos pero mismo hash son indistinguibles para el modelo.
5. **Sin reentrenamiento continuo**: El modelo v1.0.1 es estático. Nuevas familias de malware que no están en SOREL-20M podrían no ser detectadas.
6. **Sin validación sobre datos de campo reales**: No existe en el repositorio un conjunto de evaluación proveniente de análisis forense real.
