"""
tests/unit/test_settings.py — Tests unitarios de configs/settings.py.

17.4 — Cubre:
  - Defaults presentes con valores esperados
  - Secretos enmascarados en log_config
"""
import io
import logging
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestSettingsDefaults:
    """Defaults presentes con valores esperados."""

    def test_quarantine_dir_default(self):
        """QUARANTINE_DIR tiene un valor por defecto razonable."""
        from configs.settings import QUARANTINE_DIR
        assert isinstance(QUARANTINE_DIR, Path)
        assert "quarantine" in str(QUARANTINE_DIR).lower()

    def test_analysis_timeout_default(self):
        """ANALYSIS_TIMEOUT_SECONDS default = 60."""
        from configs.settings import ANALYSIS_TIMEOUT_SECONDS
        assert ANALYSIS_TIMEOUT_SECONDS == 60

    def test_behavioral_timeout_default(self):
        """BEHAVIORAL_SHIELD_TIMEOUT_SECONDS default = 2."""
        from configs.settings import BEHAVIORAL_SHIELD_TIMEOUT_SECONDS
        assert BEHAVIORAL_SHIELD_TIMEOUT_SECONDS == 2

    def test_rate_limit_default(self):
        """RATE_LIMIT_SCANS_PER_MINUTE default = 20."""
        from configs.settings import RATE_LIMIT_SCANS_PER_MINUTE
        assert RATE_LIMIT_SCANS_PER_MINUTE == 20

    def test_feature_dimension(self):
        """FEATURE_DIMENSION = 2381."""
        from configs.settings import FEATURE_DIMENSION
        assert FEATURE_DIMENSION == 2381

    def test_incidents_table(self):
        """SUPABASE_INCIDENTS_TABLE default = 'incidents'."""
        from configs.settings import SUPABASE_INCIDENTS_TABLE
        assert SUPABASE_INCIDENTS_TABLE == "incidents"


class TestLogConfig:
    """Secretos enmascarados en log_config."""

    def test_secrets_masked(self):
        """SUPABASE_KEY y SUPABASE_JWT_SECRET deben mostrarse como '***'."""
        from configs.settings import log_config

        logger = logging.getLogger("test_settings")
        logger.setLevel(logging.DEBUG)

        # Capturar mensajes del logger
        handler = logging.StreamHandler(stream=io.StringIO())
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)

        try:
            env_patch = {
                "SUPABASE_KEY": "super-secret-key",
                "SUPABASE_JWT_SECRET": "jwt-secret-123",
                "SUPABASE_URL": "https://example.supabase.co",
                "N8N_ENABLED": "true",
            }
            with patch.dict(os.environ, env_patch, clear=False):
                log_config(logger)

            output = handler.stream.getvalue()

            # Los secretos deben estar enmascarados
            assert "super-secret-key" not in output
            assert "jwt-secret-123" not in output

            # Pero los no-secretos deben aparecer legibles
            if "SUPABASE_URL" in output:
                assert "example.supabase.co" in output

        finally:
            logger.removeHandler(handler)
