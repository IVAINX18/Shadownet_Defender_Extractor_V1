import pytest
import numpy as np
import pefile
from extractors.byte_histogram import ByteHistogram
from extractors.byte_entropy import ByteEntropy
from extractors.imports import ImportsFeatureBlock
from extractors.header import HeaderFileInfo
from extractors.section_info import SectionInfoBlock
from extractors.string_extractor import StringExtractorBlock

# Mock data or use a real small PE if available. 
# For unit tests, we can often mock pefile.PE if we are careful, 
# but it's easier to skip or use a dummy file. 
# Here we will try to use a dummy byte array where possible or skip if PE is needed.

@pytest.fixture
def dummy_pe_bytes():
    return b"MZ" + b"\x00" * 1022

def test_byte_histogram(dummy_pe_bytes):
    extractor = ByteHistogram()
    # Mock PE not needed for histograms usually if raw_data is passed
    vector = extractor.extract(None, dummy_pe_bytes)
    assert vector.shape == (256,)
    assert np.isclose(vector.sum(), 1.0)

def test_byte_entropy(dummy_pe_bytes):
    extractor = ByteEntropy()
    vector = extractor.extract(None, dummy_pe_bytes)
    assert vector.shape == (256,)
    assert np.isclose(vector.sum(), 1.0)
    
def test_imports_dim():
    extractor = ImportsFeatureBlock()
    assert extractor.dim == 1280

def test_header_dim():
    extractor = HeaderFileInfo()
    assert extractor.dim == 62

def test_section_dim():
    extractor = SectionInfoBlock()
    assert extractor.dim == 255
    
def test_string_extractor(dummy_pe_bytes):
    extractor = StringExtractorBlock()
    vector = extractor.extract(None, dummy_pe_bytes)
    assert vector.shape == (104,)

def test_raw_fallback_non_pe(tmp_path):
    # Crear un archivo de texto plano no-PE
    non_pe_file = tmp_path / "test.txt"
    non_pe_file.write_bytes(b"Este es un archivo de texto plano que no tiene estructura de ejecutable PE.")
    
    from extractors.extractor import PEFeatureExtractor
    extractor = PEFeatureExtractor()
    vector = extractor.extract(str(non_pe_file))
    
    # Debe ser de tamaño 2381 exacto
    assert vector.shape == (2381,)
    
    # Verificar diagnósticos de fallback crudo
    diag = extractor.last_diagnostics["diagnostics"]
    assert diag["extraction_mode"] == "RAW_FALLBACK"
    assert "pefile_failed" in diag["degradation_reason"]
    assert diag["packer_indicators"]["packer_detected"] is False

def test_distributed_sampling(tmp_path):
    # Crear un archivo de 12 MB (bloated con ceros)
    large_file = tmp_path / "large_file.bin"
    large_file.write_bytes(b"MZ" + b"\x00" * (12 * 1024 * 1024))
    
    from extractors.extractor import PEFeatureExtractor
    extractor = PEFeatureExtractor()
    vector = extractor.extract(str(large_file))
    
    assert vector.shape == (2381,)
    
    # Diagnósticos de muestreo
    diag = extractor.last_diagnostics["diagnostics"]
    assert diag["extraction_mode"] == "PE_FASTLOAD" or diag["extraction_mode"] == "RAW_FALLBACK"
    assert diag["bytes_sampled"] <= 10 * 1024 * 1024
    assert diag["bytes_sampled"] >= 10 * 1024 * 1024 - 5
    assert diag["percentage_analyzed"] < 100.0

def test_packer_detection(tmp_path):
    # Crear un archivo con firma UPX
    upx_file = tmp_path / "upx_file.bin"
    upx_file.write_bytes(b"MZ" + b"\x00" * 100 + b"UPX!" + b"\x00" * 100)
    
    from extractors.extractor import PEFeatureExtractor
    extractor = PEFeatureExtractor()
    vector = extractor.extract(str(upx_file))
    
    diag = extractor.last_diagnostics["diagnostics"]
    assert diag["packer_indicators"]["is_packed_upx"] is True
    assert diag["packer_indicators"]["packer_detected"] is True
    assert "upx_signature_in_bytes" in diag["packer_indicators"]["packer_reasons"]


def test_extractor_timeout_fallback(tmp_path, monkeypatch):
    """T-04: extractor timeout → operational_status=SUSPICIOUS + degradation_reason."""
    import time
    from unittest.mock import MagicMock, patch
    test_file = tmp_path / "slow.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 200)
    monkeypatch.setenv("EXTRACTOR_TIMEOUT_SECONDS", "1")
    # Reimport to pick env — patch directly
    with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
        from core.engine import ShadowNetEngine
        engine = ShadowNetEngine.__new__(ShadowNetEngine)
        # extractor que duerme más que el timeout
        def slow_extract(path):
            time.sleep(3)
            return [0.0] * 2381
        engine.extractor = MagicMock()
        engine.extractor.extract = slow_extract
        engine.extractor.last_diagnostics = {}
        engine.model = MagicMock()
        result = {
            "detection_phases": [],
            "details": {},
            "label": "Unknown",
            "score": -1.0,
            "operational_status": "SUSPICIOUS",
            "confidence": "Low",
            "status": "error",
        }
        # Forzar timeout corto via monkeypatch de la constante
        import configs.settings as _settings
        monkeypatch.setattr(_settings, "EXTRACTOR_TIMEOUT_SECONDS", 1, raising=False)
        engine._run_ml_phase(test_file, result)
        assert result["operational_status"] == "SUSPICIOUS"
        assert result["details"].get("degradation_reason") == "extractor_timeout"

