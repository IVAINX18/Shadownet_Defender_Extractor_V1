"""
backend/app/config.py — Constantes de configuración centralizadas.

MAX_UPLOAD_MB se lee de entorno (por defecto 200). Mínimo 100 MB
para cumplir el requisito de archivos grandes en escaneo.

LLM_* controlan la cascada Tri-Fallover de core/llm/explanation_service.py:
groq (openai/gpt-oss-20b) -> gemini (gemini-3.5-flash-lite) -> template.
Se leen con os.getenv siguiendo el patrón del módulo (sin Pydantic Settings).
"""

from __future__ import annotations

import os

_raw_mb = int(os.getenv("MAX_UPLOAD_MB", "200"))
# Mínimo 100 MB; sin tope superior agresivo (ajustable por env si hace falta)
MAX_UPLOAD_MB = max(100, _raw_mb)
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

# ---------------------------------------------------------------------------
# LLM Tri-Fallover — proveedor, orden de cascada y modelos por proveedor.
# ExplanationService lee estos valores vía os.getenv con los mismos defaults;
# se exponen aquí para que el backend los valide/documente en un solo lugar.
# ---------------------------------------------------------------------------
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()
LLM_PROVIDER_ORDER = [
    p.strip().lower()
    for p in os.getenv("LLM_PROVIDER_ORDER", "groq,gemini,template").split(",")
    if p.strip()
]
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
GROQ_TIMEOUT_SECONDS = float(os.getenv("GROQ_TIMEOUT_SECONDS", "10"))
GEMINI_TIMEOUT_SECONDS = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "12"))
