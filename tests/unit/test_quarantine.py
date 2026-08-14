"""
tests/unit/test_quarantine.py — Tests unitarios del QuarantineManager.

16.1 — Cubre:
  - quarantine mueve archivo
  - SHA-256 en meta
  - symlink rechazado
  - path traversal rechazado
  - restore verifica SHA-256
  - directorio 700
"""
import json
import os
import platform
import stat
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.quarantine import QuarantineManager


class TestQuarantineFile:
    """quarantine_file mueve el archivo y crea metadata."""

    def test_quarantine_moves_file(self, tmp_path):
        """El archivo original debe desaparecer y aparecer en cuarentena."""
        src = tmp_path / "malware.exe"
        src.write_bytes(b"MALWARE_CONTENT_12345")
        q_dir = tmp_path / "quarantine"

        mgr = QuarantineManager(quarantine_dir=q_dir)
        result = mgr.quarantine_file(src, {"result": "malicious"})

        assert result.success is True
        assert not src.exists()
        assert result.quarantine_path.exists()
        assert result.quarantine_path.suffix == ".quar"

    def test_quarantine_sha256_in_meta(self, tmp_path):
        """El SHA-256 debe aparecer en el .meta.json y en el resultado."""
        import hashlib
        src = tmp_path / "test.exe"
        content = b"UNIQUE_CONTENT_FOR_SHA256"
        src.write_bytes(content)
        expected_sha = hashlib.sha256(content).hexdigest()
        q_dir = tmp_path / "quarantine"

        mgr = QuarantineManager(quarantine_dir=q_dir)
        result = mgr.quarantine_file(src, {"result": "malicious"})

        assert result.sha256 == expected_sha
        assert result.meta_path.exists()
        meta = json.loads(result.meta_path.read_text())
        assert meta["sha256"] == expected_sha


class TestQuarantineSecurityRejections:
    """Rechazos de seguridad: symlinks y path traversal."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="symlinks en Windows requieren privilegios")
    def test_quarantine_rejects_symlink(self, tmp_path):
        """Symlinks deben ser rechazados con SYMLINK_REJECTED."""
        real = tmp_path / "real.exe"
        real.write_bytes(b"REAL_FILE")
        link = tmp_path / "link.exe"
        link.symlink_to(real)
        q_dir = tmp_path / "quarantine"

        mgr = QuarantineManager(quarantine_dir=q_dir)
        result = mgr.quarantine_file(link, {})

        assert result.success is False
        assert result.error == "SYMLINK_REJECTED"
        # El archivo original NO debe ser modificado
        assert real.exists()

    def test_quarantine_rejects_traversal(self, tmp_path):
        """Paths con '..' deben ser rechazados con PATH_TRAVERSAL_REJECTED."""
        q_dir = tmp_path / "quarantine"

        mgr = QuarantineManager(quarantine_dir=q_dir)
        result = mgr.quarantine_file(Path("../../../etc/passwd"), {})

        assert result.success is False
        assert result.error == "PATH_TRAVERSAL_REJECTED"


class TestQuarantineRestore:
    """restore_file con verificación de integridad SHA-256."""

    def test_restore_integrity(self, tmp_path):
        """Round-trip: quarantine → restore debe preservar integridad."""
        src = tmp_path / "clean.exe"
        content = b"ORIGINAL_CONTENT_EXACT"
        src.write_bytes(content)
        q_dir = tmp_path / "quarantine"
        dest = tmp_path / "restored" / "clean.exe"

        mgr = QuarantineManager(quarantine_dir=q_dir)
        q_result = mgr.quarantine_file(src, {"result": "suspicious"})
        assert q_result.success

        r_result = mgr.restore_file(q_result.quarantine_path, dest)
        assert r_result.success is True
        assert r_result.integrity_ok is True
        assert dest.read_bytes() == content


class TestQuarantineDirectory:
    """Directorio de cuarentena creado con permisos 700."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="chmod 700 no aplica en Windows")
    def test_creates_dir_700(self, tmp_path):
        """El directorio de cuarentena debe tener permisos 700."""
        src = tmp_path / "file.exe"
        src.write_bytes(b"content")
        q_dir = tmp_path / "new_quarantine"

        mgr = QuarantineManager(quarantine_dir=q_dir)
        mgr.quarantine_file(src, {})

        mode = q_dir.stat().st_mode & 0o777
        assert mode == 0o700
