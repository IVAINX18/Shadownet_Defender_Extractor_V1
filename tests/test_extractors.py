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
