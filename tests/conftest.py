"""
tests/conftest.py — Fixtures compartidos para toda la suite de tests.

Incluye:
  - Configuración de Hypothesis (CI/dev profiles)
  - Fixtures base: tmp_path, mock_engine, test_client
  - Fixture para PE mínimo de prueba
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Asegurar project root en path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Hypothesis profiles
# ---------------------------------------------------------------------------
try:
    from hypothesis import settings, HealthCheck

    settings.register_profile(
        "ci",
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
    )
    settings.register_profile("dev", max_examples=50)
    settings.load_profile("ci")
except ImportError:
    pass  # hypothesis no instalado — tests de propiedades no correrán


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def project_root() -> Path:
    """Ruta raíz del proyecto."""
    return _PROJECT_ROOT


@pytest.fixture
def mock_engine():
    """Motor de escaneo mockeado que no carga ONNX ni YARA."""
    engine = MagicMock()
    engine.model = MagicMock()
    engine.model.predict.return_value = 0.2  # benign
    engine._yara_scanner = None
    engine._behavioral_shield = None
    return engine


@pytest.fixture
def sample_pe_bytes() -> bytes:
    """
    Bytes mínimos de un PE válido para tests.
    Contiene solo el DOS header + PE signature válidos.
    """
    # Minimal PE: DOS header (MZ) + PE signature offset + PE\0\0
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = (64).to_bytes(4, "little")  # e_lfanew → offset 64
    pe_sig = b"PE\x00\x00"
    # COFF header (20 bytes mínimo) + Optional header vacío
    coff_header = bytearray(20)
    coff_header[2:4] = (0).to_bytes(2, "little")  # NumberOfSections = 0
    coff_header[16:18] = (0).to_bytes(2, "little")  # SizeOfOptionalHeader = 0
    return bytes(dos_header) + pe_sig + bytes(coff_header) + b"\x00" * 200


@pytest.fixture
def sample_pe_file(tmp_path, sample_pe_bytes) -> Path:
    """Archivo PE mínimo temporal para tests."""
    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(sample_pe_bytes)
    return pe_file


@pytest.fixture
def non_pe_file(tmp_path) -> Path:
    """Archivo no-PE temporal para tests."""
    f = tmp_path / "not_a_pe.txt"
    f.write_text("This is not a PE file")
    return f


@pytest.fixture
def test_client():
    """TestClient de FastAPI para tests de integración."""
    try:
        from fastapi.testclient import TestClient
        from backend.app.main import app
        return TestClient(app)
    except ImportError:
        pytest.skip("httpx not installed (required for TestClient)")
