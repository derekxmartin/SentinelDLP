"""Tests for server configuration security validation."""

import logging

import pytest

from server.config import Settings, _INSECURE_JWT_SECRET, validate_production_config


class TestSecurityDefaults:
    """Verify that insecure defaults are caught by the model validator."""

    def test_default_jwt_secret_rejected_in_production(self):
        """validate_production_config raises ValueError when the default
        JWT secret is used with debug=False."""
        s = Settings(
            jwt_secret=_INSECURE_JWT_SECRET,
            debug=False,
            _env_file=None,
        )
        # Patch the module-level settings so validate_production_config
        # inspects our test instance.
        import server.config as _cfg

        original = _cfg.settings
        try:
            _cfg.settings = s
            with pytest.raises(ValueError, match="DLP_JWT_SECRET must be set"):
                validate_production_config()
        finally:
            _cfg.settings = original

    def test_default_jwt_secret_allowed_in_debug(self):
        """Default JWT secret should be allowed when debug=True."""
        s = Settings(
            jwt_secret=_INSECURE_JWT_SECRET,
            debug=True,
            _env_file=None,
        )
        assert s.jwt_secret == _INSECURE_JWT_SECRET

    def test_custom_jwt_secret_accepted(self):
        """Custom JWT secret should always be accepted."""
        s = Settings(
            jwt_secret="my-strong-secret-key-12345",
            debug=False,
            _env_file=None,
        )
        assert s.jwt_secret == "my-strong-secret-key-12345"

    def test_default_jwt_secret_logs_warning_in_debug(self, caplog):
        """A warning is logged when the default secret is used in debug mode."""
        with caplog.at_level(logging.WARNING, logger="server.config"):
            Settings(
                jwt_secret=_INSECURE_JWT_SECRET,
                debug=True,
                _env_file=None,
            )
        assert "default JWT secret" in caplog.text

    def test_default_jwt_secret_logs_critical_in_production(self, caplog):
        """A CRITICAL message is logged when the default secret is used
        with debug=False."""
        with caplog.at_level(logging.CRITICAL, logger="server.config"):
            Settings(
                jwt_secret=_INSECURE_JWT_SECRET,
                debug=False,
                _env_file=None,
            )
        assert "DLP_JWT_SECRET" in caplog.text

    def test_default_db_credentials_warning(self, caplog):
        """A warning is logged when default DB credentials are used in
        non-debug mode."""
        with caplog.at_level(logging.WARNING, logger="server.config"):
            Settings(
                jwt_secret="safe-secret",
                database_url="postgresql+asyncpg://akeso:akeso@localhost:5432/akeso_dlp",
                debug=False,
                _env_file=None,
            )
        assert "database credentials" in caplog.text.lower()

    def test_default_db_credentials_no_warning_in_debug(self, caplog):
        """No DB credentials warning when running in debug mode."""
        with caplog.at_level(logging.WARNING, logger="server.config"):
            Settings(
                jwt_secret="safe-secret",
                database_url="postgresql+asyncpg://akeso:akeso@localhost:5432/akeso_dlp",
                debug=True,
                _env_file=None,
            )
        assert "database credentials" not in caplog.text.lower()

    def test_validate_production_config_passes_with_strong_secret(self):
        """validate_production_config should not raise when a custom
        secret is configured."""
        s = Settings(
            jwt_secret="production-grade-secret-key",
            debug=False,
            _env_file=None,
        )
        import server.config as _cfg

        original = _cfg.settings
        try:
            _cfg.settings = s
            validate_production_config()  # should not raise
        finally:
            _cfg.settings = original
