"""
tests/properties/test_quarantine_properties.py — Tests de propiedades del QuarantineManager.

18.3 — Properties 5, 6, 7, 8 con Hypothesis.
"""
from __future__ import annotations

import hashlib
import platform
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from hypothesis import given, assume, settings, HealthCheck
    from hypothesis import strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

pytestmark = pytest.mark.skipif(
    not HAS_HYPOTHESIS,
    reason="hypothesis no instalado (pip install hypothesis)",
)

from core.quarantine import QuarantineManager

if HAS_HYPOTHESIS:

    @given(content=st.binary(min_size=1, max_size=1024 * 64))
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
    def test_prop5_sha256_matches_file(tmp_path, content):
        """Prop 5: sha256 del resultado == sha256 real del archivo."""
        src = tmp_path / "prop5.exe"
        src.write_bytes(content)
        q_dir = tmp_path / "q5"
        expected = hashlib.sha256(content).hexdigest()
        result = QuarantineManager(quarantine_dir=q_dir).quarantine_file(src, {})
        assert result.success is True
        assert result.sha256 == expected

    @given(content=st.binary(min_size=1, max_size=1024 * 16))
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
    def test_prop6_original_deleted_after_quarantine(tmp_path, content):
        """Prop 6: Tras quarantine_file exitosa, el archivo original no existe."""
        src = tmp_path / "prop6.exe"
        src.write_bytes(content)
        q_dir = tmp_path / "q6"
        original_path = src
        result = QuarantineManager(quarantine_dir=q_dir).quarantine_file(src, {})
        if result.success:
            assert not original_path.exists()

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="Symlinks requieren privilegios en Windows",
    )
    @given(content=st.binary(min_size=1, max_size=1024))
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
    def test_prop7_symlink_always_rejected(tmp_path, content):
        """Prop 7: quarantine_file sobre symlink → SYMLINK_REJECTED, nunca success."""
        real = tmp_path / "real7.exe"
        real.write_bytes(content)
        link = tmp_path / "link7.exe"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(real)
        q_dir = tmp_path / "q7"
        result = QuarantineManager(quarantine_dir=q_dir).quarantine_file(link, {})
        assert result.success is False
        assert result.error == "SYMLINK_REJECTED"
        assert real.exists()

    @given(content=st.binary(min_size=1, max_size=1024 * 32))
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
    def test_prop8_restore_integrity(tmp_path, content):
        """Prop 8: restore_file(q, dest) → sha256(dest) == sha256 original."""
        src = tmp_path / "prop8.exe"
        src.write_bytes(content)
        q_dir = tmp_path / "q8"
        dest = tmp_path / "restored8" / "prop8.exe"
        expected = hashlib.sha256(content).hexdigest()
        mgr = QuarantineManager(quarantine_dir=q_dir)
        q = mgr.quarantine_file(src, {})
        assume(q.success)
        r = mgr.restore_file(q.quarantine_path, dest)
        assert r.success is True
        assert r.integrity_ok is True
        assert hashlib.sha256(dest.read_bytes()).hexdigest() == expected

else:
    def test_prop5_sha256_matches_file(): pytest.skip("hypothesis no instalado")
    def test_prop6_original_deleted_after_quarantine(): pytest.skip("hypothesis no instalado")
    def test_prop7_symlink_always_rejected(): pytest.skip("hypothesis no instalado")
    def test_prop8_restore_integrity(): pytest.skip("hypothesis no instalado")
