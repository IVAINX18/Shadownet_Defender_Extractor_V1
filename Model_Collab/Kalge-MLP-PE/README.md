# Kalge-MLP-PE — Notebook único importable

- `shadownet_sorel7M.ipynb` — 15 celdas: Fase 0 (H0–H5 + H8) con puerta
  intermedia, Fase 1 (H6/H7 estructural + semántica) con veredicto final.
  `SKIP_VALIDATED=True` por defecto: si `meta.db` / `train_sha_order.npy` /
  `train_lab_surv.npy` ya existen, se omiten descargas y reconstrucción.
  (Fusionado el 2026-09-07 desde los dos notebooks de fase; los splits se
  eliminaron para no duplicar.)

## Evidencia viva verificada (red local; re-ejecutar en Kaggle)

- `HEAD processed-data/meta.db` → `200 OK`, `Content-Length: 3788979200` (~3.79 GB), `Accept-Ranges: bytes`.
- `GET Range bytes=0-3 lightGBM-features/train-features.npz` → `206 Partial Content`, `Content-Range: bytes 0-3/121046992510` (~121 GB total), magia `PK\x03\x04` (ZIP real).
- `GET Range` de cola (últimos 64 B) → `206`. Conclusión: el servidor honra Range en cabeza y cola.
- Inventario ZIP por cola (requiere ruta ZIP64 — ver bug 2026-09-07 abajo):
  `arr_0.npy` STORED, 120.9 GB, header `{'descr': '<f4', 'fortran_order': False, 'shape': (12699013, 2381)}`;
  `arr_1.npy` STORED, ~101 MB, header `{'descr': '<i8', 'fortran_order': False, 'shape': (12699013,)}`.
  Conclusión: train = **12 699 013 filas × 2381 float32** + labels int64; STORED ⇒ row-slice por Range viable (H4); 7M es submuestreo factible.

## Bug corregido 2026-09-07 (celda 3, H3)

Síntoma: `AssertionError: FAIL H3: firma CD corrupta en offset 0`.
Causa: el fichero supera 4 GB ⇒ ZIP64. El EOCD clásico trae `cd_off=0xFFFFFFFF`
(placeholder) y el offset real de 64 bits vive en el ZIP64 EOCD, localizado por la
firma `PK\x06\x07`. El código leía el CD desde el offset basura. Además el EOCD
ZIP64 usa discos de 4 bytes (formato `<QHHIIQQQQ`, 52 B) y el header del Central
Directory se parsea desde `pos+6` con `<HHHHHIIIHHHHHII`.
Corrección aplicada en la celda 3; inventario verificado en vivo (2 entradas, ambas STORED).

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

## Corrección 2026-09-07b (notebook 00, celda 5)

Constante del split train: el valor supuesto `1543449600` era incorrecto.
El oficial (`config.py` de sophos/SOREL-20M, verificado vía raw GitHub) es
`train_validation_split = 1543542570.0` (`validation_test_split = 1547279640.0`).
Celda corregida.

## Fase 1 — `01_resolucion_h6_h7.ipynb` (H6/H7)

Estado: H6/H7 en FAIL controlado tras la primera ejecución (resultado correcto:
sin mapa sha↔índice la fila no es atribuible). Este notebook los cierra.

Base legal verificada (raw GitHub sophos/SOREL-20M):
`build_numpy_arrays_for_lightgbm.py` usa `get_generator(..., shuffle=False)` y
`np.savez` en orden → el orden del npz ES el orden del Dataset = query sqlite
(rowid, sin `ORDER BY`) menos shas sin features. `generators.py` confirma que
`shuffle=False` preserva el orden aunque haya varios workers.

Método (todo streaming, cero descargas de 72 GB / 121 GB):
1. Descarga `meta.db` (3.8 GB, única descarga pesada, con reanudación) + `shas_missing_ember_features.json`.
2. Prueba estructural: query train en orden `rowid` → memmap en disco → filtro
   missing por chunks → nº supervivientes debe ser == 12699013 (si no, abortar).
3. Walk LMDB remoto validado en vivo: meta (páginas 0/1, se elige txnid mayor;
   root=12, depth=6, ~19.39M entradas) → B-tree → overflow → `zlib+msgpack`
   (`strict_map_key=False`, clave `{0: vector}`). Layout LMDB 0.9 verificado
   contra `mdb.c` oficial (meta con prefijo PAGEHDRSZ=16; nodo `lo,hi,flags,ksize`;
   `F_BIGDATA=0x01`; overflow con dato en +16). Clave real decodificada en vivo:
   `0000001f...9e58` → 2381 floats finitos con ~8 Range GETs de 4 KB.
4. Prueba semántica: 7 índices (primero, último, 5 aleatorios seed 7):
   `walk(sha[i]) == row_npz(i)` exacto + `arr_1[i] == is_malware`.
5. Artefactos: `train_sha_order.npy` (S64) + `train_lab_surv.npy` (int8) —
   subir como Kaggle Dataset privado para la fase 7M.
