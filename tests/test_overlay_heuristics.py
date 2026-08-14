"""
tests/test_overlay_heuristics.py — Tests unitarios para OverlayAnalyzer y HeuristicRiskEngine.
"""
import struct
import pytest
import numpy as np
from pathlib import Path

from core.overlay import OverlayAnalyzer, OverlayReport
from core.heuristics import HeuristicRiskEngine, RiskAssessment


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

def _make_minimal_pe(section_data: bytes = b"\x00" * 512) -> bytes:
    """
    Construye un PE minimal válido usando struct directamente.
    El offset del overlay (fin de sección) será calculable manualmente.
    """
    # Tamaño de header: DOS(64) + PE_SIG(4) + COFF(20) + OPT(240) + 1_SECTION(40) = 368 → alineado a 512
    HEADER_SIZE = 512
    SECTION_RAW_OFFSET = HEADER_SIZE
    section_size = len(section_data)
    if section_size == 0:
        section_size = 512
        section_data = b"\x00" * section_size

    # DOS header: e_magic=MZ, e_lfanew=0x40 (64)
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)

    # PE signature
    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes)
    coff = struct.pack("<HHIIIHH",
        0x8664,   # Machine: x86-64
        1,        # NumberOfSections
        0,        # TimeDateStamp
        0, 0,     # PointerToSymbolTable, NumberOfSymbols
        240,      # SizeOfOptionalHeader
        0x0022,   # Characteristics
    )

    # Optional header (240 bytes): solo magic y SizeOfHeaders obligatorio
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x020B)           # Magic PE64
    struct.pack_into("<I", opt, 60, HEADER_SIZE)      # SizeOfHeaders
    struct.pack_into("<I", opt, 56, 0x1000)           # ImageBase (lo)

    # Section table (40 bytes): una sola seción .text
    section_entry = bytearray(40)
    section_entry[0:6] = b".text\x00"
    struct.pack_into("<I", section_entry, 8,  len(section_data))  # VirtualSize
    struct.pack_into("<I", section_entry, 12, 0x1000)              # VirtualAddress
    struct.pack_into("<I", section_entry, 16, len(section_data))  # SizeOfRawData
    struct.pack_into("<I", section_entry, 20, SECTION_RAW_OFFSET) # PointerToRawData
    struct.pack_into("<I", section_entry, 36, 0x60000020)          # Characteristics

    header = bytes(dos) + pe_sig + coff + bytes(opt) + bytes(section_entry)
    header = header.ljust(HEADER_SIZE, b"\x00")
    return header + section_data


def _make_dropper(stub_size: int = 4096, payload_size: int = 20 * 1024 * 1024,
                  payload_entropy: str = "high") -> bytes:
    """Crea un archivo simulado de dropper con overlay cifrado."""
    stub = _make_minimal_pe(b"\x00" * stub_size)
    if payload_entropy == "high":
        import os
        payload = os.urandom(payload_size)
    else:
        payload = b"\x00" * payload_size
    return stub + payload


# ──────────────────────────────────────────────────────────────────────────────
# Tests: OverlayAnalyzer — Detección de overlay
# ──────────────────────────────────────────────────────────────────────────────

class TestOverlayAnalyzer:

    def test_no_overlay_for_clean_pe(self):
        """Un PE sin overlay no debe reportar overlay presente."""
        analyzer = OverlayAnalyzer()
        pe_data = _make_minimal_pe(b"\x90" * 512)
        report = analyzer.analyze(pe_data)
        assert report.overlay_present is False
        assert report.overlay_ratio == 0.0

    def test_detects_overlay_presence(self, tmp_path):
        """Un PE con datos después de las secciones debe detectar overlay."""
        analyzer = OverlayAnalyzer()
        pe_data = _make_minimal_pe(b"\x00" * 512)
        dropper = pe_data + b"\xFF" * (1024 * 1024)  # 1 MB overlay
        report = analyzer.analyze(dropper)
        assert report.overlay_present is True
        assert report.overlay_size > 0
        assert report.overlay_ratio > 0.0

    def test_overlay_ratio_correct(self, tmp_path):
        """El ratio overlay/total debe ser correcto."""
        analyzer = OverlayAnalyzer()
        stub = _make_minimal_pe(b"\x00" * 512)
        overlay = b"\xFF" * len(stub)  # overlay igual al stub = 50%
        data = stub + overlay
        report = analyzer.analyze(data)
        assert report.overlay_present is True
        assert 0.40 < report.overlay_ratio < 0.60  # Aproximadamente 50%

    def test_high_entropy_overlay(self):
        """Overlay con bytes aleatorios debe tener entropía alta."""
        import os
        analyzer = OverlayAnalyzer()
        stub = _make_minimal_pe(b"\x00" * 512)
        overlay = os.urandom(2 * 1024 * 1024)  # 2 MB aleatorio
        report = analyzer.analyze(stub + overlay)
        assert report.overlay_present is True
        assert report.overlay_entropy > 7.0

    def test_low_entropy_overlay(self):
        """Overlay con ceros debe tener entropía baja (pero ratio alto)."""
        analyzer = OverlayAnalyzer()
        stub = _make_minimal_pe(b"\x00" * 512)
        overlay = b"\x00" * (2 * 1024 * 1024)
        report = analyzer.analyze(stub + overlay)
        assert report.overlay_present is True
        assert report.overlay_entropy < 1.0  # Ceros = entropía 0

    def test_detects_embedded_mz_in_overlay(self):
        """Debe detectar un MZ embebido con e_lfanew válido en el overlay."""
        analyzer = OverlayAnalyzer()
        stub = _make_minimal_pe(b"\x00" * 512)

        # Construir un MZ con e_lfanew=0x40 y firma PE válida
        embedded_mz = b"MZ" + b"\x00" * (0x3C - 2) + struct.pack("<I", 0x40)
        embedded_mz += b"\x00" * (0x40 - len(embedded_mz))
        embedded_mz += b"PE\x00\x00" + b"\x00" * 200

        overlay = b"\xAA" * 1024 + embedded_mz + b"\xBB" * 1024
        report = analyzer.analyze(stub + overlay)
        assert report.overlay_present is True
        assert report.embedded_pe_detected is True
        assert report.embedded_pe_count >= 1

    def test_no_embedded_pe_in_clean_overlay(self):
        """Overlay de ceros no debe reportar PEs embebidos."""
        analyzer = OverlayAnalyzer()
        stub = _make_minimal_pe(b"\x00" * 512)
        overlay = b"\x00" * (1024 * 1024)
        report = analyzer.analyze(stub + overlay)
        assert report.embedded_pe_detected is False

    def test_installer_detection_nsis(self):
        """Debe detectar NSIS como instalador legítimo."""
        analyzer = OverlayAnalyzer()
        data = b"MZ" + b"\x00" * 100 + b"NullsoftInst" + b"\x00" * 1000
        report = analyzer.analyze(data)
        assert report.is_known_installer is True
        assert report.installer_type == "NSIS"

    def test_installer_detection_inno(self):
        """Debe detectar Inno Setup como instalador legítimo."""
        analyzer = OverlayAnalyzer()
        data = b"MZ" + b"\x00" * 100 + b"Inno Setup" + b"\x00" * 1000
        report = analyzer.analyze(data)
        assert report.is_known_installer is True
        assert report.installer_type == "InnoSetup"

    def test_empty_file_returns_empty_report(self):
        """Un archivo vacío no debe causar excepciones."""
        analyzer = OverlayAnalyzer()
        report = analyzer.analyze(b"")
        assert report.overlay_present is False

    def test_non_pe_file_returns_empty_report(self):
        """Un archivo no-PE no debe reportar overlay."""
        analyzer = OverlayAnalyzer()
        report = analyzer.analyze(b"Este es texto plano, no un PE.")
        assert report.overlay_present is False


# ──────────────────────────────────────────────────────────────────────────────
# Tests: HeuristicRiskEngine — Scoring
# ──────────────────────────────────────────────────────────────────────────────

class TestHeuristicRiskEngine:

    def _empty_report(self) -> OverlayReport:
        return OverlayReport()

    def _dropper_report(self) -> OverlayReport:
        r = OverlayReport()
        r.overlay_present = True
        r.overlay_size = 19 * 1024 * 1024
        r.overlay_ratio = 0.987         # 98.7%
        r.overlay_entropy = 7.9977      # casi máximo
        r.global_entropy = 7.992
        r.embedded_pe_detected = True
        r.embedded_pe_count = 1
        r.embedded_pe_offsets = [108189]
        return r

    def test_clean_file_scores_low(self):
        """Archivo sin overlay debe tener riesgo LOW y estado CLEAN."""
        engine = HeuristicRiskEngine()
        result = engine.assess(self._empty_report(), ml_score=0.02)
        assert result.risk_level == "LOW"
        assert result.operational_status == "CLEAN"
        assert result.risk_score <= 20

    def test_dropper_scores_critical(self):
        """Dropper con overlay cifrado y PE embebido debe alcanzar CRITICAL."""
        engine = HeuristicRiskEngine()
        result = engine.assess(self._dropper_report(), ml_score=0.0)
        assert result.risk_level in ("HIGH", "CRITICAL")
        assert result.operational_status in ("SUSPICIOUS", "DANGEROUS")
        # overlay_ratio > 93% (45pts) + entropy > 7.8 (35pts) + embedded_pe (25pts) = 105pts
        assert result.risk_score >= 80

    def test_yara_overlay_hit_raises_score(self):
        """YARA en overlay debe sumar 35 puntos."""
        engine = HeuristicRiskEngine()
        report = OverlayReport()
        report.overlay_present = True
        report.overlay_ratio = 0.5
        report.overlay_entropy = 6.5
        report.overlay_yara_hits = ["Trojan_GenericKD"]
        result = engine.assess(report, ml_score=0.1)
        assert result.risk_score >= 35

    def test_installer_gets_discount(self):
        """Un instalador conocido debe recibir descuento de 20 pts."""
        engine = HeuristicRiskEngine()
        report = self._dropper_report()
        report.is_known_installer = True
        report.installer_type = "InnoSetup"
        result_with_fp = engine.assess(report, ml_score=0.0)

        report2 = self._dropper_report()
        result_without_fp = engine.assess(report2, ml_score=0.0)

        assert result_with_fp.risk_score < result_without_fp.risk_score

    def test_ml_malware_always_dangerous(self):
        """Si ML da MALWARE (score >= 0.5), el estado operativo debe ser DANGEROUS."""
        engine = HeuristicRiskEngine()
        result = engine.assess(self._empty_report(), ml_score=0.95)
        assert result.operational_status == "DANGEROUS"

    def test_ml_benign_critical_heuristic_is_dangerous(self):
        """ML=BENIGN + heurística=CRITICAL → DANGEROUS (evasión detectada)."""
        engine = HeuristicRiskEngine()
        result = engine.assess(self._dropper_report(), ml_score=0.0)
        assert result.operational_status == "DANGEROUS"

    def test_ml_benign_medium_heuristic_is_suspicious(self):
        """ML=BENIGN + heurística=MEDIUM → SUSPICIOUS."""
        engine = HeuristicRiskEngine()
        report = OverlayReport()
        report.overlay_present = True
        report.overlay_ratio = 0.55      # 55% → no dispara overlay_ratio_high
        report.overlay_entropy = 7.5     # Dispara entropy_high (25pts)
        report.global_entropy = 7.6      # Dispara high_global_entropy (15pts) = 40 total → MEDIUM
        result = engine.assess(report, ml_score=0.05)
        assert result.risk_level in ("MEDIUM", "HIGH")
        assert result.operational_status == "SUSPICIOUS"

    def test_risk_assessment_to_dict(self):
        """to_dict() debe retornar todos los campos esperados."""
        engine = HeuristicRiskEngine()
        result = engine.assess(self._empty_report())
        d = result.to_dict()
        assert "risk_score" in d
        assert "risk_level" in d
        assert "operational_status" in d
        assert "triggered_indicators" in d
        assert "justification" in d

    def test_no_imports_raises_score(self):
        """Un PE sin imports debe sumar 20 puntos."""
        engine = HeuristicRiskEngine()
        packer = {"num_imports": 0, "packer_detected": False, "rwx_sections": 0}
        result = engine.assess(self._empty_report(), packer_indicators=packer)
        assert result.risk_score >= 20


# ──────────────────────────────────────────────────────────────────────────────
# Test de integración: simular el caso real de sample1.exe
# ──────────────────────────────────────────────────────────────────────────────

def test_sample1_evasion_scenario(tmp_path):
    """
    Simula exactamente el escenario de evasión detectado en sample1.exe:
    - Stub PE de 0.3 MB
    - Overlay cifrado de 19.7 MB (entropía 7.99)
    - PE embebido en el overlay
    - Resultado ML: BENIGN (score=0.0)
    
    Con las nuevas mejoras, el sistema debe clasificarlo como DANGEROUS.
    """
    import os

    # Construir el PE stub (pequeño, con estructura válida)
    stub_section = b"\x90" * 4096  # NOP sled inocente
    stub = _make_minimal_pe(stub_section)

    # Overlay cifrado con alta entropía (simular payload RC4/AES)
    overlay_size = 500 * 1024  # 500 KB para el test (más rápido que 19 MB)
    encrypted_payload = os.urandom(overlay_size)

    # PE embebido en el overlay (e_lfanew válido)
    embedded_mz = b"MZ" + b"\x00" * (0x3C - 2) + struct.pack("<I", 0x40)
    embedded_mz += b"\x00" * (0x40 - len(embedded_mz))
    embedded_mz += b"PE\x00\x00" + b"\x00" * 200
    embedded_mz = embedded_mz.ljust(1024, b"\x00")

    # Insertar el PE embebido dentro del overlay cifrado
    prefix = os.urandom(10240)   # 10 KB antes del PE embebido
    overlay = prefix + embedded_mz + encrypted_payload

    full_file = stub + overlay
    total_size = len(full_file)
    overlay_ratio = len(overlay) / total_size

    assert overlay_ratio > 0.50, "El overlay debe representar más del 50% del archivo"

    # Ejecutar análisis
    analyzer = OverlayAnalyzer()
    report = analyzer.analyze(full_file)

    # Validar detección de overlay
    assert report.overlay_present is True, "Debe detectar overlay"
    assert report.overlay_entropy > 7.0, "Overlay cifrado debe tener alta entropía"
    assert report.embedded_pe_detected is True, "Debe detectar el PE embebido"

    # Ejecutar heurística simulando que ML dijo BENIGN (score=0.0)
    engine = HeuristicRiskEngine()
    risk = engine.assess(report, packer_indicators={}, ml_score=0.0)

    # El sistema DEBE detectar el riesgo a pesar del ML
    assert risk.risk_level in ("HIGH", "CRITICAL"), \
        f"Escenario de evasión debe ser HIGH/CRITICAL, got {risk.risk_level}"
    assert risk.operational_status in ("SUSPICIOUS", "DANGEROUS"), \
        f"Estado operativo debe ser SUSPICIOUS/DANGEROUS, got {risk.operational_status}"

    print(f"\n✅ Escenario de evasión detectado:")
    print(f"   overlay_ratio={report.overlay_ratio:.1%}")
    print(f"   overlay_entropy={report.overlay_entropy:.4f}")
    print(f"   embedded_pe_count={report.embedded_pe_count}")
    print(f"   risk_score={risk.risk_score}")
    print(f"   risk_level={risk.risk_level}")
    print(f"   operational_status={risk.operational_status}")
    print(f"   triggers: {risk.triggered_indicators}")
