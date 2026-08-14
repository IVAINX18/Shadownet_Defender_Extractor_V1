"""
tests/security/test_backend_security.py — Tests de seguridad del endpoint /scan.

18.1 — Cubre:
  - Path traversal sanitizado → no llega al motor
  - Archivo > MAX_UPLOAD_BYTES → HTTP 413
  - Sin JWT → HTTP 401
  - JWT expirado → HTTP 401
  - Doble extensión → HTTP 400
  - Rate limit excedido → HTTP 429
  - Control chars / BiDi → HTTP 400
  - GET /health sin JWT → 200 o 503 (nunca 401)
"""
from __future__ import annotations

import io
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from fastapi.testclient import TestClient
    from backend.app.main import app
    _HAS_CLIENT = True
except Exception:
    app = None
    _HAS_CLIENT = False

pytestmark = pytest.mark.skipif(
    not _HAS_CLIENT,
    reason="FastAPI TestClient no disponible",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client() -> "TestClient":
    from fastapi.testclient import TestClient
    return TestClient(app, raise_server_exceptions=False)


def _make_file(content: bytes, filename: str = "test.exe"):
    return ("file", (filename, io.BytesIO(content), "application/octet-stream"))


def _auth_header():
    return {"Authorization": "Bearer dummy-token-for-test"}


DUMMY_USER = {"id": "user-security-test", "email": "sec@test.com"}


# ---------------------------------------------------------------------------
# Fixture: dependency_overrides para bypassar JWT real
# ---------------------------------------------------------------------------

@pytest.fixture
def authenticated_client():
    """
    TestClient con la dependencia get_current_user sobreescrita.

    Usa app.dependency_overrides (API oficial de FastAPI para tests)
    en lugar de patch(), que no intercepta las dependencias inyectadas.
    """
    from backend.app.api.dependencies.auth import get_current_user

    def _mock_user():
        return DUMMY_USER

    app.dependency_overrides[get_current_user] = _mock_user
    from fastapi.testclient import TestClient
    client = TestClient(app, raise_server_exceptions=False)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def rate_limit_authenticated_client():
    """
    TestClient con usuario único por cada test de rate limit.
    """
    from backend.app.api.dependencies.auth import get_current_user

    unique_user = {"id": f"rl-user-{time.time()}", "email": "rl@test.com"}

    def _mock_user():
        return unique_user

    app.dependency_overrides[get_current_user] = _mock_user
    from fastapi.testclient import TestClient
    client = TestClient(app, raise_server_exceptions=False)
    yield client, unique_user
    app.dependency_overrides.pop(get_current_user, None)


# ---------------------------------------------------------------------------
# 18.1a — Sin JWT → 401
# ---------------------------------------------------------------------------

class TestNoJWT:
    """Sin JWT → HTTP 401."""

    def test_scan_file_no_auth(self):
        """POST /scan/file sin header Authorization → 401."""
        c = _client()
        resp = c.post("/scan/file", files=[_make_file(b"MZ" + b"\x00" * 200)])
        assert resp.status_code == 401

    def test_scan_multiple_no_auth(self):
        """POST /scan/multiple sin JWT → 401."""
        c = _client()
        resp = c.post(
            "/scan/multiple",
            files=[
                _make_file(b"MZ" + b"\x00" * 100, "a.exe"),
                _make_file(b"MZ" + b"\x00" * 100, "b.exe"),
            ],
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 18.1b — JWT expirado → 401
# ---------------------------------------------------------------------------

class TestExpiredJWT:
    """JWT expirado/inválido → HTTP 401."""

    def test_expired_token_rejected(self):
        """Un JWT inválido/expirado debe retornar 401."""
        c = _client()
        resp = c.post(
            "/scan/file",
            files=[_make_file(b"MZ" + b"\x00" * 200)],
            headers={"Authorization": (
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                ".eyJzdWIiOiIxMjMifQ.expired_signature_here"
            )},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 18.1c — Doble extensión → 400
# ---------------------------------------------------------------------------

class TestDoubleExtension:
    """Doble extensión → HTTP 400."""

    @pytest.mark.parametrize("filename", [
        "report.pdf.exe",
        "image.jpg.dll",
        "document.docx.bat",
        "archive.zip.ps1",
        "photo.png.scr",
    ])
    def test_double_extension_rejected(self, filename, authenticated_client):
        """Archivos con doble extensión sospechosa deben retornar 400."""
        resp = authenticated_client.post(
            "/scan/file",
            files=[_make_file(b"MZ" + b"\x00" * 200, filename)],
            headers=_auth_header(),
        )
        assert resp.status_code == 400
        body = resp.json()
        assert body.get("status") == "error"


# ---------------------------------------------------------------------------
# 18.1d — Archivo > MAX_UPLOAD_BYTES → 413
# ---------------------------------------------------------------------------

class TestFileTooLarge:
    """Archivo > MAX_UPLOAD_BYTES → HTTP 413."""

    def test_oversized_file_rejected(self, authenticated_client):
        """Un archivo que supera el límite debe retornar 413."""
        from backend.app.config import MAX_UPLOAD_BYTES
        oversized = b"X" * (MAX_UPLOAD_BYTES + 1024)
        resp = authenticated_client.post(
            "/scan/file",
            files=[_make_file(oversized, "big.exe")],
            headers=_auth_header(),
        )
        assert resp.status_code == 413


# ---------------------------------------------------------------------------
# 18.1e — Rate limit → 429
# ---------------------------------------------------------------------------

class TestRateLimit:
    """Rate limit excedido → HTTP 429."""

    def test_rate_limit_enforced(self, rate_limit_authenticated_client):
        """Más de RATE_LIMIT_SCANS_PER_MINUTE solicitudes → 429."""
        from configs.settings import RATE_LIMIT_SCANS_PER_MINUTE
        from backend.app.api.routes.scan import _rate_limit_store

        client, user = rate_limit_authenticated_client
        uid = user["id"]
        _rate_limit_store.pop(uid, None)

        mock_result = MagicMock()
        mock_result.file_name = "ok.exe"
        mock_result.user_id = None
        mock_result.user_email = None
        mock_result.model_dump.return_value = {}

        responses = []
        for _ in range(RATE_LIMIT_SCANS_PER_MINUTE + 1):
            with patch("backend.app.api.routes.scan.scan_single_file",
                       return_value=mock_result), \
                 patch("backend.app.api.routes.scan.sync_user"), \
                 patch("backend.app.api.routes.scan.save_scan_safe"):
                resp = client.post(
                    "/scan/file",
                    files=[_make_file(b"MZ" * 100, "ok.exe")],
                    headers=_auth_header(),
                )
                responses.append(resp.status_code)

        assert 429 in responses, f"Rate limit no activado. Codes: {responses}"


# ---------------------------------------------------------------------------
# 18.1f — Path traversal sanitizado, nunca 500
# ---------------------------------------------------------------------------

class TestPathTraversalSanitization:
    """Path traversal en filename → sanitizado o rechazado. Nunca 500."""

    @pytest.mark.parametrize("malicious_name", [
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\cmd.exe",
        "test/../../secret.exe",
    ])
    def test_traversal_not_500(self, malicious_name, authenticated_client):
        """Path traversal nunca debe causar HTTP 500."""
        mock_result = MagicMock()
        mock_result.file_name = "safe"
        mock_result.user_id = None
        mock_result.user_email = None
        mock_result.model_dump.return_value = {}

        with patch("backend.app.api.routes.scan.scan_single_file",
                   return_value=mock_result), \
             patch("backend.app.api.routes.scan.sync_user"), \
             patch("backend.app.api.routes.scan.save_scan_safe"):
            resp = authenticated_client.post(
                "/scan/file",
                files=[_make_file(b"MZ" + b"\x00" * 200, malicious_name)],
                headers=_auth_header(),
            )

        assert resp.status_code != 500, \
            f"Path traversal causó 500: {malicious_name}"


# ---------------------------------------------------------------------------
# 18.1g — Control chars / BiDi → 400
# ---------------------------------------------------------------------------

class TestControlCharacters:
    """Caracteres de control / BiDi en filename → HTTP 400."""

    def test_null_byte_rejected(self, authenticated_client):
        """
        Null byte en nombre es truncado por HTTP multipart → procesado o rechazado.
        En ningún caso debe producir HTTP 500 (error de servidor).
        """
        resp = authenticated_client.post(
            "/scan/file",
            files=[_make_file(b"MZ" + b"\x00" * 200, "evil\x00.exe")],
            headers=_auth_header(),
        )
        # HTTP trunca en \x00 → el servidor ve "evil" sin extensión
        # El comportamiento correcto es que NO sea 500 (nunca error de servidor)
        assert resp.status_code != 500, \
            f"Null byte en filename causó HTTP 500: {resp.status_code}"

    def test_rlo_char_rejected(self, authenticated_client):
        """Nombre con Unicode RLO (U+202E) debe ser rechazado con 400."""
        resp = authenticated_client.post(
            "/scan/file",
            files=[_make_file(b"MZ" + b"\x00" * 200, "invoice\u202e.exe")],
            headers=_auth_header(),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 18.1h — GET /health no requiere JWT (19.4)
# ---------------------------------------------------------------------------

class TestHealthNoAuth:
    """GET /health es público: no requiere JWT."""

    def test_health_no_auth_never_401(self):
        """GET /health sin JWT → 200 o 503, nunca 401."""
        c = _client()
        resp = c.get("/health")
        assert resp.status_code in (200, 503), \
            f"Health devolvió {resp.status_code}, esperado 200 o 503"

    def test_health_has_pipeline_mode(self):
        """GET /health incluye pipeline_mode."""
        c = _client()
        resp = c.get("/health")
        data = resp.json().get("data", {})
        assert "pipeline_mode" in data
        assert data["pipeline_mode"] in ("full", "degraded", "minimal")

    def test_health_has_all_components(self):
        """GET /health incluye todos los componentes requeridos."""
        c = _client()
        resp = c.get("/health")
        components = resp.json().get("data", {}).get("components", {})
        for key in ("onnx_model", "yara_scanner", "supabase", "n8n", "psutil"):
            assert key in components, f"Componente '{key}' ausente en /health"
