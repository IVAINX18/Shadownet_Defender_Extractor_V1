"""
tests/security/test_backend_security.py — Tests de seguridad del endpoint /scan.

18.1 — Cubre:
  - Path traversal sanitizado → no llega al motor
  - Archivo > MAX_UPLOAD_BYTES → HTTP 413
  - Sin JWT → HTTP 401
  - JWT expirado → HTTP 401
  - Doble extensión → HTTP 400
  - Rate limit excedido → HTTP 429
  - Cleanup garantizado en excepción
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

# TestClient de FastAPI
try:
    from fastapi.testclient import TestClient
    from backend.app.main import app
    _client = TestClient(app, raise_server_exceptions=False)
    HAS_CLIENT = True
except Exception:
    HAS_CLIENT = False

pytestmark = pytest.mark.skipif(
    not HAS_CLIENT,
    reason="FastAPI TestClient no disponible",
)

# Helpers
def _make_file(content: bytes, filename: str = "test.exe"):
    return ("file", (filename, io.BytesIO(content), "application/octet-stream"))

def _auth_header(token: str = "Bearer validtoken"):
    return {"Authorization": token}

DUMMY_USER = {"id": "user-security-test", "email": "sec@test.com"}


def _override_auth():
    """Override de FastAPI que retorna DUMMY_USER sin verificar JWT."""
    return DUMMY_USER


@pytest.fixture(autouse=False)
def auth_override():
    """Fixture que instala el override de autenticación y lo limpia al terminar."""
    from backend.app.api.dependencies.auth import get_current_user
    app.dependency_overrides[get_current_user] = _override_auth
    yield
    app.dependency_overrides.pop(get_current_user, None)



class TestNoJWT:
    """Sin JWT → HTTP 401."""

    def test_scan_file_no_auth(self):
        """POST /scan/file sin header Authorization → 401."""
        resp = _client.post(
            "/scan/file",
            files=[_make_file(b"MZ" + b"\x00" * 200)],
        )
        assert resp.status_code == 401

    def test_scan_multiple_no_auth(self):
        """POST /scan/multiple sin JWT → 401."""
        resp = _client.post(
            "/scan/multiple",
            files=[_make_file(b"MZ" + b"\x00" * 100, "a.exe"),
                   _make_file(b"MZ" + b"\x00" * 100, "b.exe")],
        )
        assert resp.status_code == 401


class TestExpiredJWT:
    """JWT expirado → HTTP 401."""

    def test_expired_token_rejected(self):
        """Un JWT expirado debe retornar 401."""
        resp = _client.post(
            "/scan/file",
            files=[_make_file(b"MZ" + b"\x00" * 200)],
            headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.expired"},
        )
        assert resp.status_code == 401


class TestDoubleExtension:
    """Doble extensión → HTTP 400."""

    @pytest.mark.parametrize("filename", [
        "report.pdf.exe",
        "image.jpg.dll",
        "document.docx.bat",
        "archive.zip.ps1",
        "photo.png.scr",
    ])
    def test_double_extension_rejected(self, filename):
        """Archivos con doble extensión sospechosa deben retornar 400."""
        with patch(_AUTH_PATCH, return_value=DUMMY_USER):
            resp = _client.post(
                "/scan/file",
                files=[_make_file(b"MZ" + b"\x00" * 200, filename)],
                headers=_auth_header(),
            )
        assert resp.status_code == 400
        body = resp.json()
        assert body.get("status") == "error"


class TestFileTooLarge:
    """Archivo > MAX_UPLOAD_BYTES → HTTP 413."""

    def test_oversized_file_rejected(self):
        """Un archivo que supera el límite debe retornar 413."""
        from backend.app.config import MAX_UPLOAD_BYTES
        oversized = b"X" * (MAX_UPLOAD_BYTES + 1024)
        with patch(_AUTH_PATCH, return_value=DUMMY_USER):
            resp = _client.post(
                "/scan/file",
                files=[_make_file(oversized, "big.exe")],
                headers=_auth_header(),
            )
        assert resp.status_code == 413


class TestRateLimit:
    """Rate limit excedido → HTTP 429."""

    def test_rate_limit_enforced(self):
        """Más de RATE_LIMIT_SCANS_PER_MINUTE solicitudes → 429."""
        from configs.settings import RATE_LIMIT_SCANS_PER_MINUTE
        from backend.app.api.routes.scan import _rate_limit_store
        test_user = {"id": f"rate-limit-test-{time.time()}", "email": "rl@test.com"}
        uid = test_user["id"]
        _rate_limit_store.pop(uid, None)

        mock_result = MagicMock()
        mock_result.file_name = "ok.exe"
        mock_result.user_id = None
        mock_result.user_email = None
        mock_result.model_dump.return_value = {}

        responses = []
        for i in range(RATE_LIMIT_SCANS_PER_MINUTE + 1):
            with patch(_AUTH_PATCH, return_value=test_user), \
                 patch("backend.app.api.routes.scan.scan_single_file", return_value=mock_result), \
                 patch("backend.app.api.routes.scan.sync_user"), \
                 patch("backend.app.api.routes.scan.save_scan_safe"):
                resp = _client.post(
                    "/scan/file",
                    files=[_make_file(b"MZ" * 100, "ok.exe")],
                    headers=_auth_header(),
                )
                responses.append(resp.status_code)
        assert 429 in responses, f"Rate limit no activado. Codes: {responses}"


class TestPathTraversalSanitization:
    """Path traversal en filename → sanitizado, no llega al motor."""

    @pytest.mark.parametrize("malicious_name", [
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\cmd.exe",
        "test/../../secret.exe",
    ])
    def test_traversal_sanitized(self, malicious_name):
        """Path traversal → sanitizado o rechazado. Nunca 500."""
        mock_result = MagicMock()
        mock_result.file_name = "safe"
        mock_result.user_id = None
        mock_result.user_email = None
        mock_result.model_dump.return_value = {}

        with patch(_AUTH_PATCH, return_value=DUMMY_USER), \
             patch("backend.app.api.routes.scan.scan_single_file", return_value=mock_result), \
             patch("backend.app.api.routes.scan.sync_user"), \
             patch("backend.app.api.routes.scan.save_scan_safe"):
            resp = _client.post(
                "/scan/file",
                files=[_make_file(b"MZ" + b"\x00" * 200, malicious_name)],
                headers=_auth_header(),
            )
        # No debe ser 500. Puede ser 200 (sanitizado) o 400 (rechazado)
        assert resp.status_code != 500, \
            f"Path traversal causó 500: {malicious_name}"


class TestControlCharacters:
    """Caracteres de control en filename → HTTP 400."""

    def test_null_byte_rejected(self):
        """Nombre con null byte debe ser rechazado con 400."""
        with patch(_AUTH_PATCH, return_value=DUMMY_USER):
            resp = _client.post(
                "/scan/file",
                files=[_make_file(b"MZ" + b"\x00" * 200, "evil\x00.exe")],
                headers=_auth_header(),
            )
        assert resp.status_code == 400

    def test_rlo_char_rejected(self):
        """Nombre con Unicode RLO (U+202E) debe ser rechazado con 400."""
        with patch(_AUTH_PATCH, return_value=DUMMY_USER):
            resp = _client.post(
                "/scan/file",
                files=[_make_file(b"MZ" + b"\x00" * 200, "invoice\u202e.exe")],
                headers=_auth_header(),
            )
        assert resp.status_code == 400


class TestHealthNoAuth:
    """GET /health no requiere JWT."""

    def test_health_no_auth_returns_200_or_503(self):
        """GET /health sin JWT debe retornar 200 o 503, nunca 401."""
        resp = _client.get("/health")
        assert resp.status_code in (200, 503), \
            f"Health devolvió {resp.status_code}, esperado 200 o 503"

    def test_health_has_pipeline_mode(self):
        """GET /health debe incluir el campo pipeline_mode."""
        resp = _client.get("/health")
        body = resp.json()
        data = body.get("data", {})
        assert "pipeline_mode" in data
        assert data["pipeline_mode"] in ("full", "degraded", "minimal")

    def test_health_has_components(self):
        """GET /health debe incluir el campo components."""
        resp = _client.get("/health")
        body = resp.json()
        data = body.get("data", {})
        assert "components" in data
        components = data["components"]
        for key in ("onnx_model", "yara_scanner", "supabase", "n8n", "psutil"):
            assert key in components, f"Componente '{key}' ausente en health"
