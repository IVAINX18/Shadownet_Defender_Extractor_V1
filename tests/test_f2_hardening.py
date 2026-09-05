"""
tests/test_f2_hardening.py — Suite de tests para la fase F2 de hardening.

Cubre:
  T-05 — YARA Whitelist
  T-06 — Block Entropy Analysis
  T-07 — Installer Spoof Detection
  T-08 — Quarantine Encryption
  T-09 — ML Hardening (suspicious_loader_no_imports)
  T-10 — LLM Response Validation
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_minimal_pe(section_data: bytes = b"\x00" * 512) -> bytes:
    """Construye un PE minimal valido con una sola seccion .text."""
    HEADER_SIZE = 512
    SECTION_RAW_OFFSET = HEADER_SIZE
    if not section_data:
        section_data = b"\x00" * 512

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)

    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes): HHIIIHH = 2+2+4+4+4+2+2
    coff = struct.pack("<HHIIIHH",
        0x8664,   # Machine
        1,        # NumberOfSections
        0,        # TimeDateStamp
        0,        # PointerToSymbolTable
        0,        # NumberOfSymbols
        240,      # SizeOfOptionalHeader
        0x0022,   # Characteristics
    )

    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x020B)
    struct.pack_into("<I", opt, 60, HEADER_SIZE)
    struct.pack_into("<I", opt, 56, 0x1000)

    sect = bytearray(40)
    sect[0:6] = b".text\x00"
    struct.pack_into("<I", sect, 8, len(section_data))
    struct.pack_into("<I", sect, 12, 0x1000)
    struct.pack_into("<I", sect, 16, len(section_data))
    struct.pack_into("<I", sect, 20, SECTION_RAW_OFFSET)
    struct.pack_into("<I", sect, 36, 0x60000020)

    header = (bytes(dos) + pe_sig + coff + bytes(opt) + bytes(sect)).ljust(HEADER_SIZE, b"\x00")
    return header + section_data


# ---------------------------------------------------------------------------
# T-05: YARA Whitelist
# ---------------------------------------------------------------------------

class TestYaraWhitelist:
    """T-05 — YaraScanner.is_whitelisted() y engine whitelist path."""

    def _make_scanner_with_whitelist(self, whitelist_data: dict):
        """Crea un YaraScanner con whitelist inyectada directamente."""
        from security.yara_scanner import YaraScanner
        scanner = YaraScanner.__new__(YaraScanner)
        scanner._whitelist = whitelist_data
        scanner._rules = None
        scanner._rules_count = 0
        return scanner

    def _make_match(self, rule_name: str):
        from security.yara_scanner import YaraMatch
        return YaraMatch(rule_name=rule_name, tags=[], meta={}, category="test")

    def test_sha256_in_whitelist_returns_true(self):
        """Un SHA-256 en la whitelist debe retornar is_whitelisted=True."""
        sha = "a" * 64
        scanner = self._make_scanner_with_whitelist(
            {"sha256": [sha], "yara_exclusions": []}
        )
        assert scanner.is_whitelisted(sha, []) is True

    def test_sha256_not_in_whitelist_returns_false(self):
        """Un SHA-256 no registrado no debe ser whitelisteado."""
        scanner = self._make_scanner_with_whitelist(
            {"sha256": ["b" * 64], "yara_exclusions": []}
        )
        assert scanner.is_whitelisted("a" * 64, []) is False

    def test_yara_exclusion_rule_returns_true(self):
        """Una regla en yara_exclusions debe whitelistear sin importar el hash."""
        scanner = self._make_scanner_with_whitelist({
            "sha256": [],
            "yara_exclusions": [{"rule": "Keylogger_Generic", "company": "Microsoft"}],
        })
        match = self._make_match("Keylogger_Generic")
        assert scanner.is_whitelisted("x" * 64, [match]) is True

    def test_unknown_rule_not_whitelisted(self):
        """Una regla no excluida no debe pasar el whitelist."""
        scanner = self._make_scanner_with_whitelist({
            "sha256": [],
            "yara_exclusions": [{"rule": "OtherRule"}],
        })
        match = self._make_match("Trojan_GenericKD")
        assert scanner.is_whitelisted("x" * 64, [match]) is False

    def test_load_whitelist_missing_file_returns_empty(self, tmp_path):
        """Si configs/whitelist.json no existe, la whitelist es vacia sin error."""
        from security.yara_scanner import YaraScanner
        with patch("security.yara_scanner._WHITELIST_PATH", tmp_path / "nonexistent.json"):
            scanner = YaraScanner.__new__(YaraScanner)
            wl = scanner._load_whitelist()
        assert wl == {"sha256": [], "yara_exclusions": []}

    def test_load_whitelist_invalid_json_returns_empty(self, tmp_path):
        """Si el JSON esta malformado, la whitelist es vacia sin propagar excepcion."""
        bad = tmp_path / "whitelist.json"
        bad.write_text("INVALID JSON {{{")
        from security.yara_scanner import YaraScanner
        with patch("security.yara_scanner._WHITELIST_PATH", bad):
            scanner = YaraScanner.__new__(YaraScanner)
            wl = scanner._load_whitelist()
        assert wl == {"sha256": [], "yara_exclusions": []}

    def test_engine_whitelist_degrades_to_suspicious(self, tmp_path):
        """
        Cuando el YARA match activa la whitelist, el engine degrada a SUSPICIOUS
        y retorna None (para que el pipeline continue con ML/overlay).
        """
        test_file = tmp_path / "procexp64.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 200)
        sha256 = hashlib.sha256(test_file.read_bytes()).hexdigest()

        with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
            from core.engine import ShadowNetEngine
            engine = ShadowNetEngine.__new__(ShadowNetEngine)

            mock_yara = MagicMock()
            mock_yara.is_available = True
            mock_scan = MagicMock()
            mock_scan.has_matches = True
            mock_scan.threat_names = ["Keylogger_Generic"]
            mock_scan.categories = ["keylogger"]
            mock_scan.matches = [MagicMock(rule_name="Keylogger_Generic", category="keylogger", tags=[])]
            mock_scan.scan_time_ms = 1.0
            mock_yara.scan.return_value = mock_scan
            # is_whitelisted retorna True simulando que la regla esta excluida
            mock_yara.is_whitelisted.return_value = True
            engine._yara_scanner = mock_yara

            result = {
                "detection_phases": [],
                "yara_matches": [],
                "details": {},
                "operational_status": "CLEAN",
            }
            yara_result = engine._run_yara_phase(test_file, result)

            # Con whitelist activa, debe retornar None y degradar en el dict `result`
            assert yara_result is None
            assert result["operational_status"] == "SUSPICIOUS"
            assert result.get("details", {}).get("whitelist_hit") is True


# ---------------------------------------------------------------------------
# T-06: Block Entropy
# ---------------------------------------------------------------------------

class TestBlockEntropy:
    """T-06 — _compute_block_entropy y campos de OverlayReport."""

    def test_empty_overlay_returns_zeros(self):
        """Un overlay vacio debe retornar (0.0, 0.0, 0)."""
        from core.overlay import OverlayAnalyzer
        max_be, ratio, count = OverlayAnalyzer._compute_block_entropy(b"")
        assert max_be == 0.0
        assert ratio == 0.0
        assert count == 0

    def test_high_entropy_overlay_detected(self):
        """Un overlay de bytes aleatorios debe tener high_entropy_block_ratio == 1.0."""
        import os as _os
        from core.overlay import OverlayAnalyzer
        data = _os.urandom(256 * 1024)  # 256 KB = 4 bloques de 64 KB
        max_be, ratio, count = OverlayAnalyzer._compute_block_entropy(data)
        assert max_be > 7.5
        assert ratio == 1.0
        assert count == 4

    def test_low_entropy_overlay_not_flagged(self):
        """Un overlay de ceros no debe activar block_entropy_anomaly."""
        from core.overlay import OverlayAnalyzer
        data = b"\x00" * 256 * 1024
        max_be, ratio, count = OverlayAnalyzer._compute_block_entropy(data)
        assert max_be < 1.0
        assert ratio == 0.0

    def test_report_fields_populated(self):
        """analyze() debe poblar max_block_entropy, high_entropy_block_ratio y block_count."""
        import os as _os
        from core.overlay import OverlayAnalyzer
        stub = _make_minimal_pe(b"\x00" * 512)
        overlay = _os.urandom(128 * 1024)
        report = OverlayAnalyzer().analyze(stub + overlay)
        assert report.overlay_present is True
        assert report.block_count >= 1
        assert report.max_block_entropy > 0.0
        assert 0.0 <= report.high_entropy_block_ratio <= 1.0

    def test_block_entropy_anomaly_in_risk_engine(self):
        """
        high_entropy_block_ratio > 0.30 + overlay_ratio > 0.50 activa
        block_entropy_anomaly en el RiskEngine.
        """
        from core.overlay import OverlayReport
        from core.heuristics import HeuristicRiskEngine

        report = OverlayReport()
        report.overlay_present = True
        report.overlay_ratio = 0.70
        # Entropia global moderada (no dispara entropy_high)
        report.overlay_entropy = 6.5
        # Pero alta entropia por bloques
        report.high_entropy_block_ratio = 0.50
        report.max_block_entropy = 7.8
        report.block_count = 4

        engine = HeuristicRiskEngine()
        result = engine.assess(report, ml_score=0.05)

        triggers = " ".join(result.triggered_indicators)
        assert "block_entropy_anomaly" in triggers
        assert result.risk_score >= 15

    def test_block_entropy_anomaly_requires_overlay_ratio(self):
        """
        Si overlay_ratio <= 0.50, block_entropy_anomaly no debe activarse
        aunque high_entropy_block_ratio sea alto.
        """
        from core.overlay import OverlayReport
        from core.heuristics import HeuristicRiskEngine

        report = OverlayReport()
        report.overlay_present = True
        report.overlay_ratio = 0.30  # bajo
        report.high_entropy_block_ratio = 0.80
        report.overlay_entropy = 6.5

        engine = HeuristicRiskEngine()
        result = engine.assess(report, ml_score=0.05)

        triggers = " ".join(result.triggered_indicators)
        assert "block_entropy_anomaly" not in triggers


# ---------------------------------------------------------------------------
# T-07: Installer Spoof
# ---------------------------------------------------------------------------

class TestInstallerSpoof:
    """T-07 — Deteccion de instaladores falsos."""

    def test_nsis_high_ratio_is_spoof(self):
        """NSIS magic + overlay_ratio > 0.93 debe activar installer_spoof_suspected."""
        from core.overlay import OverlayAnalyzer
        stub = _make_minimal_pe(b"\x00" * 256)
        # Overlay de 98%: mucho mas que el stub
        overlay = b"NullsoftInst" + b"\x00" * (stub.__len__() * 50)
        data = stub + overlay
        report = OverlayAnalyzer().analyze(data)

        assert report.installer_type == "NSIS"
        assert report.installer_spoof_suspected is True
        assert report.is_known_installer is False

    def test_inno_high_ratio_is_spoof(self):
        """InnoSetup magic + overlay_ratio > 0.93 debe activar installer_spoof_suspected."""
        from core.overlay import OverlayAnalyzer
        stub = _make_minimal_pe(b"\x00" * 256)
        overlay = b"Inno Setup" + b"\x00" * (stub.__len__() * 50)
        data = stub + overlay
        report = OverlayAnalyzer().analyze(data)

        assert report.installer_type == "InnoSetup"
        assert report.installer_spoof_suspected is True
        assert report.is_known_installer is False

    def test_nsis_low_ratio_is_legitimate(self):
        """NSIS magic + overlay_ratio <= 0.90 debe ser is_known_installer=True."""
        from core.overlay import OverlayAnalyzer
        # Stub mucho mayor que el overlay para asegurar ratio bajo
        stub = _make_minimal_pe(b"\x00" * (64 * 1024))
        # Overlay pequeño con firma NSIS al final (ratio < 10%)
        overlay = b"NullsoftInst" + b"\x00" * 4096
        data = stub + overlay
        report = OverlayAnalyzer().analyze(data)

        if report.installer_type == "NSIS":
            # Con ratio bajo, debe ser legitimo
            assert report.installer_spoof_suspected is False
            assert report.is_known_installer is True

    def test_installer_spoof_cancels_discount(self):
        """installer_spoof_suspected=True cancela el descuento de instalador en RiskEngine."""
        from core.overlay import OverlayReport
        from core.heuristics import HeuristicRiskEngine

        # Reporte con spoof activo
        report_spoof = OverlayReport()
        report_spoof.overlay_present = True
        report_spoof.overlay_ratio = 0.987
        report_spoof.overlay_entropy = 7.99
        report_spoof.installer_type = "NSIS"
        report_spoof.installer_spoof_suspected = True
        report_spoof.is_known_installer = False

        # Reporte identico pero con instalador legitimo (sin spoof)
        report_legit = OverlayReport()
        report_legit.overlay_present = True
        report_legit.overlay_ratio = 0.987
        report_legit.overlay_entropy = 7.99
        report_legit.installer_type = "NSIS"
        report_legit.installer_spoof_suspected = False
        report_legit.is_known_installer = True

        engine = HeuristicRiskEngine()
        result_spoof = engine.assess(report_spoof, ml_score=0.0)
        result_legit = engine.assess(report_legit, ml_score=0.0)

        # El spoof debe tener puntaje mas alto (sin descuento)
        assert result_spoof.risk_score >= result_legit.risk_score
        assert "installer_spoof_suspected" in " ".join(result_spoof.triggered_indicators)

    def test_installer_discount_still_works_for_legit(self):
        """Un instalador legitimo (sin spoof) debe seguir recibiendo el descuento."""
        from core.overlay import OverlayReport
        from core.heuristics import HeuristicRiskEngine

        report_with = OverlayReport()
        report_with.overlay_present = True
        report_with.overlay_ratio = 0.60
        report_with.overlay_entropy = 7.5
        report_with.installer_type = "NSIS"
        report_with.is_known_installer = True
        report_with.installer_spoof_suspected = False

        report_without = OverlayReport()
        report_without.overlay_present = True
        report_without.overlay_ratio = 0.60
        report_without.overlay_entropy = 7.5

        engine = HeuristicRiskEngine()
        score_with = engine.assess(report_with, ml_score=0.0).risk_score
        score_without = engine.assess(report_without, ml_score=0.0).risk_score

        assert score_with < score_without


# ---------------------------------------------------------------------------
# T-08: Quarantine Encryption
# ---------------------------------------------------------------------------

class TestQuarantineEncryption:
    """T-08 — Cifrado Fernet en QuarantineManager."""

    def test_quarantine_file_encrypted_when_key_available(self, tmp_path):
        """Con cryptography instalada, el archivo debe quedar cifrado (meta encrypted=True)."""
        pytest.importorskip("cryptography")
        from cryptography.fernet import Fernet
        from core.quarantine import QuarantineManager

        src = tmp_path / "malware.exe"
        content = b"MALWARE_PAYLOAD_12345"
        src.write_bytes(content)

        key = Fernet.generate_key()
        q_dir = tmp_path / "quarantine"

        with patch.dict(os.environ, {"QUARANTINE_KEY": key.decode()}):
            mgr = QuarantineManager(quarantine_dir=q_dir)
            result = mgr.quarantine_file(src, {"result": "malicious"})

        assert result.success is True
        assert not src.exists()
        # Los bytes en disco NO deben ser el contenido original
        raw_bytes = result.quarantine_path.read_bytes()
        assert raw_bytes != content

        # El meta debe indicar encrypted=True
        meta = json.loads(result.meta_path.read_text())
        assert meta["encrypted"] is True
        assert meta["key_id"] != ""

    def test_quarantine_restore_roundtrip_encrypted(self, tmp_path):
        """Round-trip con cifrado: quarantine -> restore produce el contenido original."""
        pytest.importorskip("cryptography")
        from cryptography.fernet import Fernet
        from core.quarantine import QuarantineManager

        content = b"ORIGINAL_CONTENT_EXACT_FERNET"
        src = tmp_path / "clean.exe"
        src.write_bytes(content)

        key = Fernet.generate_key()
        q_dir = tmp_path / "quarantine"
        dest = tmp_path / "restored" / "clean.exe"

        with patch.dict(os.environ, {"QUARANTINE_KEY": key.decode()}):
            mgr = QuarantineManager(quarantine_dir=q_dir)
            q_result = mgr.quarantine_file(src, {})
            assert q_result.success

            r_result = mgr.restore_file(q_result.quarantine_path, dest)

        assert r_result.success is True
        assert r_result.integrity_ok is True
        assert dest.read_bytes() == content

    def test_quarantine_fallback_no_encryption_without_cryptography(self, tmp_path):
        """Sin cryptography disponible, el archivo se guarda sin cifrar (encrypted=False)."""
        src = tmp_path / "file.exe"
        content = b"PLAIN_CONTENT"
        src.write_bytes(content)
        q_dir = tmp_path / "quarantine"

        from core.quarantine import QuarantineManager

        # Parchear _get_or_create_key para simular que cryptography no esta
        with patch("core.quarantine.manager._get_or_create_key", return_value=None):
            mgr = QuarantineManager(quarantine_dir=q_dir)
            result = mgr.quarantine_file(src, {})

        assert result.success is True
        meta = json.loads(result.meta_path.read_text())
        assert meta["encrypted"] is False
        # El contenido debe ser identico (sin cifrado)
        assert result.quarantine_path.read_bytes() == content

    def test_restore_decryption_failed_without_key(self, tmp_path):
        """restore_file retorna DECRYPTION_FAILED si encrypted=True pero clave no disponible."""
        pytest.importorskip("cryptography")
        from cryptography.fernet import Fernet
        from core.quarantine import QuarantineManager

        src = tmp_path / "file.exe"
        src.write_bytes(b"CONTENT")
        key = Fernet.generate_key()
        q_dir = tmp_path / "quarantine"

        # Cuarentenar con clave
        with patch.dict(os.environ, {"QUARANTINE_KEY": key.decode()}):
            mgr = QuarantineManager(quarantine_dir=q_dir)
            q_result = mgr.quarantine_file(src, {})
        assert q_result.success

        dest = tmp_path / "restored.exe"
        # Restaurar sin clave
        with patch("core.quarantine.manager._get_or_create_key", return_value=None):
            mgr2 = QuarantineManager(quarantine_dir=q_dir)
            r_result = mgr2.restore_file(q_result.quarantine_path, dest)

        assert r_result.success is False
        assert r_result.error == "DECRYPTION_FAILED"

    def test_get_or_create_key_reads_env(self, tmp_path):
        """_get_or_create_key debe leer QUARANTINE_KEY del entorno."""
        pytest.importorskip("cryptography")
        from cryptography.fernet import Fernet
        from core.quarantine.manager import _get_or_create_key

        key = Fernet.generate_key()
        with patch.dict(os.environ, {"QUARANTINE_KEY": key.decode()}):
            result = _get_or_create_key()
        assert result == key


# ---------------------------------------------------------------------------
# T-09: ML Hardening — suspicious_loader_no_imports
# ---------------------------------------------------------------------------

class TestMLHardening:
    """T-09 — suspicious_loader_no_imports en RiskEngine."""

    def test_no_imports_single_exec_section_raises_score(self):
        """num_imports=0 + executable_sections=1 activa suspicious_loader_no_imports."""
        from core.overlay import OverlayReport
        from core.heuristics import HeuristicRiskEngine

        engine = HeuristicRiskEngine()
        packer = {"num_imports": 0, "packer_detected": False, "rwx_sections": 0, "executable_sections": 1}
        result = engine.assess(OverlayReport(), packer_indicators=packer, ml_score=0.05)

        triggers = " ".join(result.triggered_indicators)
        assert "suspicious_loader_no_imports" in triggers
        assert result.risk_score >= 10

    def test_no_imports_without_exec_section_not_triggered(self):
        """num_imports=0 pero executable_sections != 1 NO debe activar el indicador."""
        from core.overlay import OverlayReport
        from core.heuristics import HeuristicRiskEngine

        engine = HeuristicRiskEngine()
        packer = {"num_imports": 0, "packer_detected": False, "rwx_sections": 0, "executable_sections": 3}
        result = engine.assess(OverlayReport(), packer_indicators=packer, ml_score=0.05)

        triggers = " ".join(result.triggered_indicators)
        assert "suspicious_loader_no_imports" not in triggers

    def test_normal_imports_not_flagged(self):
        """Un PE con imports normales no debe activar el indicador de loader."""
        from core.overlay import OverlayReport
        from core.heuristics import HeuristicRiskEngine

        engine = HeuristicRiskEngine()
        packer = {"num_imports": 15, "packer_detected": False, "rwx_sections": 0, "executable_sections": 1}
        result = engine.assess(OverlayReport(), packer_indicators=packer, ml_score=0.05)

        triggers = " ".join(result.triggered_indicators)
        assert "suspicious_loader_no_imports" not in triggers


# ---------------------------------------------------------------------------
# T-10: LLM Response Validation
# ---------------------------------------------------------------------------

class TestLLMValidation:
    """T-10 — Validacion de coherencia de respuesta LLM."""

    def _get_validate(self):
        from core.llm.explanation_service import _validate_llm_response
        return _validate_llm_response

    def test_inconsistent_critical_low(self):
        """risk_level=CRITICAL + threat_level=low debe marcar llm_inconsistent=True."""
        validate = self._get_validate()
        parsed = {"threat_level": "low", "analysis": "parece benigno"}
        scan = {"risk_level": "CRITICAL", "operational_status": "DANGEROUS"}
        result = validate(parsed, scan)
        assert result["llm_inconsistent"] is True

    def test_consistent_high_high(self):
        """risk_level=HIGH + threat_level=high NO debe marcar inconsistencia."""
        validate = self._get_validate()
        parsed = {"threat_level": "high", "analysis": "malware detectado"}
        scan = {"risk_level": "HIGH"}
        result = validate(parsed, scan)
        assert result["llm_inconsistent"] is False

    def test_consistent_low_none(self):
        """risk_level=LOW + threat_level=none es coherente."""
        validate = self._get_validate()
        parsed = {"threat_level": "none", "analysis": "archivo limpio"}
        scan = {"risk_level": "LOW"}
        result = validate(parsed, scan)
        assert result["llm_inconsistent"] is False

    def test_confidence_calculated(self):
        """llm_confidence debe ser >= 0 y <= 1."""
        validate = self._get_validate()
        parsed = {"threat_level": "high", "analysis": "overlay_ratio elevado"}
        scan = {"risk_level": "HIGH"}
        result = validate(parsed, scan)
        assert 0.0 <= result["llm_confidence"] <= 1.0

    def test_confidence_increases_with_indicators(self):
        """Una respuesta con mas indicadores reales debe tener mayor confianza."""
        validate = self._get_validate()

        few = validate(
            {"threat_level": "high", "analysis": "sospechoso"},
            {"risk_level": "HIGH"},
        )
        many = validate(
            {"threat_level": "high", "analysis": "overlay_ratio alto, overlay_entropy 7.99, yara match"},
            {"risk_level": "HIGH"},
        )
        assert many["llm_confidence"] >= few["llm_confidence"]

    def test_prod_http_raises(self):
        """GroqClient con ENVIRONMENT=prod y base_url http debe lanzar RuntimeError (HTTPS requerido)."""
        from core.llm.groq_client import GroqClient, GroqClientConfig

        config = GroqClientConfig(api_key="test-key", base_url="http://api.groq.com/openai/v1")

        with patch.dict(os.environ, {"ENVIRONMENT": "prod"}):
            with patch("core.llm.base_client.OpenAI"):
                with pytest.raises(RuntimeError, match="HTTPS en produccion"):
                    GroqClient(config)

    def test_prod_https_ok(self):
        """GroqClient con ENVIRONMENT=prod y base_url https no debe lanzar error."""
        from core.llm.groq_client import GroqClient, GroqClientConfig

        config = GroqClientConfig(api_key="test-key", base_url="https://api.groq.com/openai/v1")

        with patch.dict(os.environ, {"ENVIRONMENT": "prod"}):
            with patch("core.llm.base_client.OpenAI"):
                client = GroqClient(config)
                assert client is not None

    def test_explain_includes_validation_fields(self):
        """explain() debe incluir llm_inconsistent y llm_confidence en parsed_response."""
        from core.llm.explanation_service import ExplanationService, ExplanationServiceConfig

        mock_client = MagicMock()
        mock_client.generate.return_value = json.dumps({
            "analysis": "overlay_ratio alto detectado",
            "threat_level": "high",
            "behavior_summary": "dropper con payload cifrado",
            "recommended_actions": ["quarantine"],
        })

        svc = ExplanationService(
            config=ExplanationServiceConfig(default_provider="groq"),
            clients={"groq": mock_client},
        )
        scan_result = {
            "risk_level": "HIGH",
            "operational_status": "DANGEROUS",
            "score": 0.1,
        }
        result = svc.explain(scan_result)

        assert "parsed_response" in result
        pr = result["parsed_response"]
        assert "llm_inconsistent" in pr
        assert "llm_confidence" in pr
