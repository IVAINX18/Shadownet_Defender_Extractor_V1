"""
backend/app/config.py — Constantes de configuración centralizadas.

MAX_UPLOAD_MB se lee de entorno (por defecto 200). Mínimo 100 MB
para cumplir el requisito de archivos grandes en escaneo.
"""

from __future__ import annotations

import os

_raw_mb = int(os.getenv("MAX_UPLOAD_MB", "200"))
# Mínimo 100 MB; sin tope superior agresivo (ajustable por env si hace falta)
MAX_UPLOAD_MB = max(100, _raw_mb)
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
