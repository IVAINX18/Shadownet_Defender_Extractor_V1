"""
scripts/e2e_test.py — Test E2E completo de ShadowNet Defender.

Simulo un flujo real de usuario:
  1. Login con Supabase (usando SUPABASE_ANON_KEY desde .env)
  2. Escaneo de todos los archivos en samples/
  3. Generación de explicación con Ollama
  4. Verificación de persistencia en Supabase

Leo TODAS las credenciales desde .env — nunca hardcodeo valores sensibles.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import request
from urllib.error import HTTPError, URLError

# Cargo variables desde .env
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _PROJECT_ROOT / ".env"


def _load_env() -> None:
    """Leo el archivo .env y cargo las variables al entorno."""
    if not _ENV_PATH.exists():
        print(f"❌ Archivo .env no encontrado en: {_ENV_PATH}")
        sys.exit(1)

    for line in _ENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


_load_env()

# --- Configuración desde .env ---
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
BACKEND_URL = "http://127.0.0.1:8000"
SAMPLES_DIR = _PROJECT_ROOT / "samples"

# Credenciales de prueba
TEST_EMAIL = "usuario_prueba@demo.com"
TEST_PASSWORD = "12345678"


# ====================================================================
# Funciones de utilidad
# ====================================================================

def _mask_token(token: str) -> str:
    """Enmascaro el token para no exponerlo en logs."""
    if len(token) > 20:
        return token[:15] + "..." + token[-5:]
    return "***"


def _http_request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: Dict[str, str] | None = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Wrapper HTTP que maneja errores y retorna JSON parseado.
    Retorna dict con 'ok', 'status', 'data' o 'error'.
    """
    headers = headers or {}
    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
            return {"ok": True, "status": resp.status, "data": body}
    except HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode()[:500]
        except Exception:
            pass
        return {"ok": False, "status": e.code, "error": str(e), "body": body_text}
    except URLError as e:
        return {"ok": False, "status": 0, "error": str(e), "body": ""}
    except Exception as e:
        return {"ok": False, "status": 0, "error": str(e), "body": ""}


# ====================================================================
# 1. LOGIN
# ====================================================================

def login() -> Optional[str]:
    """
    Hago login en Supabase Auth y obtengo el access_token.
    Leo SUPABASE_URL y SUPABASE_ANON_KEY del entorno (.env).
    """
    if not SUPABASE_URL:
        print("❌ SUPABASE_URL no configurada en .env")
        return None
    if not SUPABASE_ANON_KEY:
        print("❌ SUPABASE_ANON_KEY no configurada en .env")
        return None

    print("=" * 60)
    print("1. LOGIN CON SUPABASE")
    print("=" * 60)
    print(f"   URL: {SUPABASE_URL}/auth/v1/token")
    print(f"   Email: {TEST_EMAIL}")

    t0 = time.time()
    result = _http_request(
        f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
        method="POST",
        data=json.dumps({"email": TEST_EMAIL, "password": TEST_PASSWORD}).encode(),
        headers={
            "Content-Type": "application/json",
            "apikey": SUPABASE_ANON_KEY,
        },
        timeout=15,
    )
    elapsed = time.time() - t0

    if not result["ok"]:
        print(f"   ❌ Login falló ({elapsed:.1f}s): {result['error']}")
        if result.get("body"):
            print(f"   Body: {result['body'][:200]}")
        return None

    data = result["data"]
    token = data.get("access_token", "")
    if not token:
        print(f"   ❌ No hay access_token en la respuesta")
        return None

    print(f"   ✅ Login exitoso ({elapsed:.1f}s)")
    print(f"   Token: {_mask_token(token)}")
    print(f"   User: {data.get('user', {}).get('email', '?')}")
    return token


# ====================================================================
# 2. SCAN FILE
# ====================================================================

def scan_file(file_path: Path, token: str) -> Optional[Dict[str, Any]]:
    """
    Envío un archivo al endpoint /scan/file con autenticación JWT.
    Construyo el multipart/form-data manualmente (sin dependencias externas).
    """
    boundary = "----ShadowNetE2E"
    body = io.BytesIO()
    body.write(f"--{boundary}\r\n".encode())
    body.write(
        f'Content-Disposition: form-data; name="file"; filename="{file_path.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
    )
    body.write(file_path.read_bytes())
    body.write(f"\r\n--{boundary}--\r\n".encode())

    t0 = time.time()
    result = _http_request(
        f"{BACKEND_URL}/scan/file",
        method="POST",
        data=body.getvalue(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        timeout=60,
    )
    elapsed = time.time() - t0

    if not result["ok"]:
        print(f"   ❌ {file_path.name:28s} ERROR ({elapsed:.1f}s): {result['error']}")
        return None

    data = result["data"].get("data", {})
    res = data.get("result", "?")
    risk = data.get("risk_level", "?")
    conf = data.get("confidence", 0)
    atype = data.get("analysis_type", "?")
    icon = {"benign": "🟢", "suspicious": "🟡", "malicious": "🔴"}.get(res, "⚪")

    print(
        f"   {icon} {file_path.name:28s} result={res:12s} risk={risk:8s} "
        f"conf={conf:.4f} type={atype:8s} t={elapsed:.2f}s"
    )
    return data


# ====================================================================
# 3. EXPLAIN (LLM)
# ====================================================================

def explain(scan_data: Dict[str, Any], token: str) -> Optional[Dict[str, Any]]:
    """
    Envío un scan_result al endpoint /analysis/explain para que Ollama
    genere una explicación técnica. Si el LLM falla o hace timeout,
    el backend retorna un fallback (no error).
    """
    payload = json.dumps({
        "scan_result": scan_data,
        "provider": "ollama",
    }).encode()

    t0 = time.time()
    result = _http_request(
        f"{BACKEND_URL}/analysis/explain",
        method="POST",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=120,
    )
    elapsed = time.time() - t0

    if not result["ok"]:
        print(f"   ❌ Explain falló ({elapsed:.1f}s): {result['error']}")
        return None

    data = result["data"].get("data", {})
    expl = data.get("explanation", "")
    llm = data.get("llm", {})
    llm_status = llm.get("status", "?")

    print(f"   LLM status: {llm_status}")
    print(f"   Provider: {llm.get('provider')}/{llm.get('model')}")
    print(f"   Time: {elapsed:.1f}s")
    print(f"   Explanation length: {len(expl)} chars")

    if llm_status == "timeout":
        print("   ⚠️  LLM timeout → fallback response")
    elif expl and len(expl) > 50:
        print(f"   ✅ Explanation: {expl[:200]}...")
    elif expl:
        print(f"   ⚠️  Short explanation: {expl}")
    else:
        print("   ⚠️  Empty explanation")

    return data


# ====================================================================
# 4. SUPABASE VERIFICATION
# ====================================================================

def verify_supabase() -> None:
    """
    Verifico que los resultados estén persistidos en Supabase.
    Uso SUPABASE_SERVICE_ROLE_KEY para acceder a la API REST.
    """
    if not SUPABASE_SERVICE_ROLE_KEY:
        print("   ⚠️  SUPABASE_SERVICE_ROLE_KEY no disponible — omito verificación")
        return

    # Verifico users
    r = _http_request(
        f"{SUPABASE_URL}/rest/v1/users?select=id,email&limit=5",
        headers={
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        },
        timeout=10,
    )
    if r["ok"]:
        users = r["data"]
        print(f"   Users: {len(users)} registro(s)")
        for u in users:
            print(f"     {u['id'][:12]}... {u['email']}")
    else:
        print(f"   ❌ Users query falló: {r['error']}")

    # Verifico scan_results (últimos 10)
    r = _http_request(
        f"{SUPABASE_URL}/rest/v1/scan_results"
        f"?select=file_name,result,risk_level,user_id,user_email,explanation"
        f"&order=created_at.desc&limit=10",
        headers={
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        },
        timeout=10,
    )
    if r["ok"]:
        scans = r["data"]
        print(f"   Scans: {len(scans)} registro(s)")
        for s in scans:
            uid = str(s.get("user_id", ""))[:12]
            expl_len = len(s.get("explanation") or "")
            print(
                f"     {s['file_name']:28s} {s['result']:12s} "
                f"uid={uid}... expl={expl_len}ch"
            )

        # Validaciones
        if scans:
            has_uid = all(s.get("user_id") for s in scans)
            has_email = all(s.get("user_email") for s in scans)
            no_enum = all("." not in str(s.get("result", "")) for s in scans)
            print(f"   user_id present:    {'✅' if has_uid else '❌'}")
            print(f"   user_email present: {'✅' if has_email else '❌'}")
            print(f"   result clean (no enum): {'✅' if no_enum else '❌'}")
    else:
        print(f"   ❌ Scans query falló: {r['error']}")


# ====================================================================
# MAIN — Flujo completo E2E
# ====================================================================

def main() -> None:
    """Ejecuto el test E2E completo."""

    # --- 0. Health check ---
    print("=" * 60)
    print("0. HEALTH CHECK")
    print("=" * 60)
    r = _http_request(f"{BACKEND_URL}/health", timeout=5)
    if not r["ok"]:
        print(f"   ❌ Backend no responde: {r['error']}")
        print("   Ejecuta: uvicorn backend.app.main:app --reload")
        sys.exit(1)
    print(f"   ✅ Backend OK: {r['data']}")

    # --- 1. Login ---
    print()
    token = login()
    if not token:
        print("\n❌ LOGIN FALLÓ — deteniendo test")
        sys.exit(1)

    # --- 2. Scan all files ---
    print()
    print("=" * 60)
    files = sorted([f for f in SAMPLES_DIR.iterdir() if f.is_file()])
    print(f"2. ESCANEO DE {len(files)} ARCHIVOS")
    print("=" * 60)

    scan_results: List[Dict[str, Any]] = []
    errors: List[str] = []

    for fp in files:
        try:
            data = scan_file(fp, token)
            if data:
                scan_results.append(data)
            else:
                errors.append(fp.name)
        except Exception as exc:
            print(f"   ❌ {fp.name}: excepción: {exc}")
            errors.append(fp.name)

    # Resumen de escaneo
    print()
    total = len(scan_results)
    benign = sum(1 for r in scan_results if r.get("result") == "benign")
    suspicious = sum(1 for r in scan_results if r.get("result") == "suspicious")
    malicious = sum(1 for r in scan_results if r.get("result") == "malicious")
    print(f"   Escaneados: {total}/{len(files)}")
    print(f"   🟢 Benign: {benign}  🟡 Suspicious: {suspicious}  🔴 Malicious: {malicious}")
    print(f"   ❌ Errores: {len(errors)}")
    if errors:
        for e in errors:
            print(f"     - {e}")

    # --- 3. LLM Explain (con el primer resultado exitoso) ---
    print()
    print("=" * 60)
    print("3. EXPLICACIÓN LLM (Ollama)")
    print("=" * 60)

    if scan_results:
        # Elijo el primer resultado para generar explicación
        explain_target = scan_results[0]
        print(f"   Archivo: {explain_target.get('file_name')}")
        explain_data = explain(explain_target, token)
    else:
        print("   ⚠️  No hay resultados para explicar")

    # --- 4. Supabase verification ---
    print()
    print("=" * 60)
    print("4. VERIFICACIÓN SUPABASE")
    print("=" * 60)
    time.sleep(1)  # Espero un momento para que las escrituras terminen
    verify_supabase()

    # --- 5. Reporte final ---
    print()
    print("=" * 60)
    print("5. REPORTE FINAL")
    print("=" * 60)
    print(f"   Backend:          ✅ Running")
    print(f"   Auth:             ✅ JWT via Supabase ANON_KEY")
    print(f"   Scanned:          {total}/{len(files)} archivos")
    print(f"   Classification:   🟢{benign} 🟡{suspicious} 🔴{malicious}")
    print(f"   Errors:           {len(errors)}")
    if scan_results:
        has_uid = all(r.get("user_id") for r in scan_results)
        has_email = all(r.get("user_email") for r in scan_results)
        has_type = all(r.get("analysis_type") for r in scan_results)
        print(f"   user_id:          {'✅' if has_uid else '❌'}")
        print(f"   user_email:       {'✅' if has_email else '❌'}")
        print(f"   analysis_type:    {'✅' if has_type else '❌'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
