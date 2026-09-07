# Kalge-MLP-PE — Fase 0: Validación (sin entrenamiento)

Master — esta carpeta contendrá el pipeline SOREL-20M → Shadow-Net FFNN.
Por ahora SOLO existe la fase de validación:

- `00_validacion_acceso_sorel.ipynb` — 8 celdas (1 markdown + 7 código).

## Evidencia viva verificada el 2026-09-07 (fuera de Kaggle, red local)

- `HEAD processed-data/meta.db` → `200 OK`, `Content-Length: 3788979200` (~3.79 GB), `Accept-Ranges: bytes`.
- `GET Range bytes=0-3 lightGBM-features/train-features.npz` → `206 Partial Content`, `Content-Range: bytes 0-3/121046992510` (~121 GB total), magia `PK\x03\x04` (ZIP real).
- `GET Range` de cola (últimos 64 B) → `206`. Conclusión: el servidor honra Range en cabeza y cola.

## Hipótesis por celda

| Celda | Hipótesis | Qué verifica | Criterio PASS/FAIL |
|---|---|---|---|
| 0 entorno | H0: no asumir GPU/VRAM/RAM/disco | Detecta torch/CUDA, VRAM, RAM, `df /kaggle/working`, exige >6 GB libres | FAIL si <6 GB |
| 1 acceso | H1: bucket público sin credenciales | HEAD a meta.db, ember data.mdb, train.npz, missing-json; exige 200 + `Accept-Ranges: bytes` | FAIL si no-200 o sin Range |
| 2 range | H2: Range honrado con 206 | Range cabeza (magia PK) + Range cola; deriva tamaño total | FAIL si no-206 o sin `PK` |
| 3 zip | H3: npz inspeccionable por cola | Lee EOCD en últimos 128 KB, recorre Central Directory, lista `.npy`, lee método compresión | FAIL si sin EOCD o sin `.npy`; informa STORED vs DEFLATED |
| 4 vector | H4/H5: row-slice streaming + 2381 finitas | Lee Local File Header; si STORED: parsea header `.npy`, calcula `payload+i*row_bytes`, trae 1 fila por Range; exige shape (2381,) y `isfinite` | Si DEFLATED → FAIL explícito + plan B (shards Parquet). Si len≠2381 o NaN/Inf → FAIL |
| 5 cruce | H6/H7: orden NO asumido + etiqueta trazable | Descarga meta.db completo (sqlite exige fichero local), verifica esquema y conteo train `rl_fs_t<=1543449600`; declara que sin mapa sha↔índice la fila NO es atribuible | Sin mapa → FAIL controlado (resultado correcto de validar, no éxito fingido) |
| 6 overlay | H8: N sin fijar, solo deterministas | 7 candidatas con veredicto OK/?/NO; pasan solo las 3 puras de SecInfo; overlay_ratio/entropy reales RECHAZADAS sin binario | Informativa; N queda abierto |
| 7 veredicto | Puerta dura | Agrega H1–H8; cualquier no-PASS → `SystemExit` abortando | Solo luz verde si todo PASS |

## Decisiones pendientes (fases siguientes, en orden)

1. Resolver H4 (STORED vs DEFLATED) + H6 (mapa sha↔índice o shards Parquet con sha).
2. Selección 7M estratificada del split train oficial, seed fija, sin leakage.
3. Scaler parcial, DataLoader streaming, FFNN, métricas, checkpoint, export ONNX (`X=[EMBER_2381|OVERLAY_N]`).
