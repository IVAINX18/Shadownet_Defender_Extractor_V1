"""
backend/app/api/dependencies/auth.py — Dependencia de autenticación Supabase.

Valido el JWT de Supabase Auth en cada request protegido.
Extraigo user_id y email del token sin hacer llamadas HTTP a Supabase
para cada request (los JWKS se cachean).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request

logger = logging.getLogger("backend.auth")

# Config
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "").strip()

# Cache para JWKS (se carga una sola vez)
_jwks_client: Optional[Any] = None


def _get_jwks_client() -> Any:
    """Crea y cachea un PyJWKClient para el JWKS endpoint de Supabase."""
    global _jwks_client
    if _jwks_client is not None:
        return _jwks_client

    import jwt

    if not SUPABASE_URL:
        return None

    jwks_url = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
    try:
        _jwks_client = jwt.PyJWKClient(jwks_url)
        logger.info("JWKS client inicializado: %s", jwks_url)
        return _jwks_client
    except Exception as exc:
        logger.warning("No se pudo inicializar JWKS client: %s", exc)
        return None


def _decode_token(token: str) -> Dict[str, Any]:
    """
    Decodifica un JWT de Supabase soportando ES256 (JWKS) y HS256 (secret).

    Intenta primero con JWKS (ES256, proyectos modernos de Supabase),
    y si falla usa HS256 con SUPABASE_JWT_SECRET como fallback.
    """
    import jwt

    # Intento 1: ES256 via JWKS
    jwks = _get_jwks_client()
    if jwks is not None:
        try:
            signing_key = jwks.get_signing_key_from_jwt(token)
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["ES256"],
                audience="authenticated",
            )
        except Exception as exc:
            logger.debug("JWKS decode falló (intentando HS256): %s", exc)

    # Intento 2: HS256 con secret
    if SUPABASE_JWT_SECRET:
        return jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated",
        )

    raise jwt.InvalidTokenError("No se pudo verificar el token (sin JWKS ni JWT_SECRET)")


async def get_current_user(request: Request) -> Dict[str, Any]:
    """
    Dependencia FastAPI que valida el JWT de Supabase Auth.

    Returns:
        {"id": "<uuid>", "email": "<email>"}

    Raises:
        HTTPException 401: Si falta el token, es inválido o expiró.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Token de autenticación requerido. Envía: Authorization: Bearer <token>",
        )

    token = auth_header[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token vacío.")

    if not SUPABASE_URL and not SUPABASE_JWT_SECRET:
        logger.warning("Supabase no configurado — modo fail-secure (401)")
        raise HTTPException(
            status_code=401,
            detail="Autenticación no disponible. Configura SUPABASE_URL o SUPABASE_JWT_SECRET.",
        )

    try:
        import jwt as pyjwt
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="Dependencia de autenticación no instalada (pip install PyJWT).",
        )

    try:
        payload = _decode_token(token)
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado. Inicia sesión nuevamente.")
    except pyjwt.InvalidTokenError as exc:
        logger.warning("JWT inválido: %s", type(exc).__name__)
        raise HTTPException(status_code=401, detail="Token inválido.")
    except Exception as exc:
        # Capturar cualquier excepción no anticipada (e.g., error de red en JWKS)
        logger.error("Error inesperado en validación JWT: %s", type(exc).__name__)
        raise HTTPException(status_code=401, detail="Error de autenticación.")

    user_id = payload.get("sub")
    email = payload.get("email")

    if not user_id:
        raise HTTPException(status_code=401, detail="Token no contiene información de usuario.")

    user = {"id": user_id, "email": email or ""}
    # F0: nunca loggear token/JWT raw; solo user_id fingerprint
    logger.debug("Usuario autenticado: %s (%s)", user_id[:8] + "***" if user_id else "***", email)
    return user
