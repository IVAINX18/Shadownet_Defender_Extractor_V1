"""
core/overlay_features.py — Contrato de features ML de overlay (ShadowNetFeatures_v1.1).

Define el bloque OVERLAY_N que se concatena al vector EMBER_2381:

    X = [EMBER_2381 | OVERLAY_N]

Diseno deliberado (limitacion documentada, no equivalencia fingida):
  - El OverlayAnalyzer forense trabaja sobre BYTES crudos del PE (entropia del
    overlay, strings, firmas MZ, PEs embebidos). Esos campos NO son reproducibles
    desde el vector EMBER-2381 y NO se incluyen aqui.
  - Este bloque solo usa el bloque General del vector (indices 616:626), cuya
    semantica EMBER ([size, vsize, has_debug, exports, imports, reloc, resources,
    signature, tls, symbols]) es identica en SOREL y en el extractor local.
  - Los indices de seccion (688:943) se excluyen a proposito: el layout de ese
    bloque no esta verificado como identico entre SOREL y el extractor local.
  - Cada feature es funcion pura y determinista del vector: sin labels, sin
    veredictos, sin fuga de informacion. Vale igual en entrenamiento (SOREL) que
    en produccion (vector del extractor local).

Orden canonico: OVERLAY_FEATURE_NAMES. Produccion y entrenamiento deben usar
exactamente este orden (ver tests/test_overlay_contract.py).
"""
from __future__ import annotations

import numpy as np

# Indices EMBER del bloque General (canonicos en SOREL y en el extractor local).
IDX_SIZE = 616       # tamano del archivo en bytes
IDX_VSIZE = 617      # SizeOfImage (tamano de la imagen en memoria)
IDX_IMPORTS = 620    # numero de imports
IDX_CERT = 623       # 1 si existe tabla de certificados (vive en zona overlay)

# Umbrales con justificacion documentada (no tuning):
# - SLACK_MIN_SIGNIFICANT: el analizador forense ignora overlays < 512 bytes.
# - STUB_MAX_IMPORTS: stubs dropper tipicos importan un punado de APIs.
# - STUB_MIN_SLACK: patron documentado sample1.exe (~98.7% del archivo fuera del stub).
SLACK_MIN_SIGNIFICANT = 512
STUB_MAX_IMPORTS = 5
STUB_MIN_SLACK = 0.5

OVERLAY_FEATURE_NAMES = [
    "slack_ratio",          # 0: fraccion del archivo mas alla de la imagen (proxy de overlay_ratio)
    "slack_bytes_log",      # 1: log1p de los bytes extra (magnitud absoluta del slack)
    "file_size_log",        # 2: log1p del tamano (contexto de escala)
    "imports_log",          # 3: log1p de imports (indicador de stub: pocos imports)
    "has_cert",             # 4: 1.0 si hay tabla de certificados (overlay legitimo; guard anti-FP)
    "stub_overlay_pattern", # 5: 1.0 si patron stub+payload (pocos imports y slack grande)
]

N_OVERLAY = len(OVERLAY_FEATURE_NAMES)


def compute_overlay_features(x: np.ndarray) -> np.ndarray:
    """Calcula el bloque OVERLAY_N desde vectores EMBER-2381.

    Acepta un vector (2381,) o un lote (n, 2381) y devuelve (N,) o (n, N)
    en float32. Funcion pura: mismo input siempre da mismo output.
    """
    v = np.asarray(x, dtype=np.float64)
    single = v.ndim == 1
    if single:
        v = v[np.newaxis, :]
    if v.shape[1] < IDX_CERT + 1:
        raise ValueError(f"vector demasiado corto: {v.shape[1]} < {IDX_CERT + 1}")

    size = np.maximum(v[:, IDX_SIZE], 0.0)
    vsize = np.maximum(v[:, IDX_VSIZE], 0.0)
    imports = np.maximum(v[:, IDX_IMPORTS], 0.0)
    cert = v[:, IDX_CERT]

    # Bytes mas alla de la imagen en memoria. Si no hay tamano o la imagen
    # cubre todo el archivo, el slack es cero (conservador: evita falsas alarmas
    # en modo RAW_FALLBACK, donde vsize llega en 0).
    slack = np.where(size > 0, np.maximum(size - vsize, 0.0), 0.0)
    with np.errstate(divide="ignore", invalid="ignore"):
        slack_ratio = np.where(size > 0, slack / np.maximum(size, 1.0), 0.0)
    slack_ratio = np.clip(slack_ratio, 0.0, 1.0)

    out = np.empty((v.shape[0], N_OVERLAY), dtype=np.float64)
    out[:, 0] = slack_ratio
    out[:, 1] = np.log1p(slack)
    out[:, 2] = np.log1p(size)
    out[:, 3] = np.log1p(imports)
    out[:, 4] = (cert != 0.0).astype(np.float64)
    out[:, 5] = ((imports <= STUB_MAX_IMPORTS) & (slack_ratio > STUB_MIN_SLACK)).astype(np.float64)

    result = out.astype(np.float32)
    return result[0] if single else result
