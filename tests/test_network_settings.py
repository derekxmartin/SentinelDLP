"""Tests for network settings API (P5-T5)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from server.api.network_settings import (
    HttpProxySettings,
    NetworkMode,
    NetworkSettingsResponse,
    SmtpRelaySettings,
    _load_settings,
    _save_settings,
    SETTINGS_FILE,
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestNetworkMode:
    def test_monitor_value(self):
        assert NetworkMode.MONITOR == "monitor"

    def test_prevent_value(self):
        assert NetworkMode.PREVENT == "prevent"


class TestHttpProxySettings:
    def test_defaults(self):
        s = HttpProxySettings()
        assert s.mode == NetworkMode.MONITOR
        assert s.block_threshold == 1
        assert s.domain_allowlist == []

    def test_prevent_mode(self):
        s = HttpProxySettings(mode=NetworkMode.PREVENT, block_threshold=5)
        assert s.mode == NetworkMode.PREVENT
        assert s.block_threshold == 5

    def test_domain_allowlist(self):
        s = HttpProxySettings(domain_allowlist=["example.com", "test.org"])
        assert len(s.domain_allowlist) == 2
        assert "example.com" in s.domain_allowlist


class TestSmtpRelaySettings:
    def test_defaults(self):
        s = SmtpRelaySettings()
        assert s.mode == NetworkMode.MONITOR
        assert s.upstream_host == "mailhog"
        assert s.upstream_port == 1025
        assert s.block_threshold == 5
        assert s.modify_threshold == 1
        assert s.quarantine_address == "quarantine@dlp.local"

    def test_custom_values(self):
        s = SmtpRelaySettings(
            mode=NetworkMode.PREVENT,
            upstream_host="smtp.local",
            upstream_port=587,
            block_threshold=10,
            modify_threshold=3,
            quarantine_address="admin@corp.com",
        )
        assert s.mode == NetworkMode.PREVENT
        assert s.upstream_port == 587
        assert s.block_threshold == 10


class TestNetworkSettingsResponse:
    def test_defaults(self):
        r = NetworkSettingsResponse()
        assert r.http_proxy.mode == NetworkMode.MONITOR
        assert r.smtp_relay.mode == NetworkMode.MONITOR

    def test_serialization_roundtrip(self):
        r = NetworkSettingsResponse(
            http_proxy=HttpProxySettings(
                mode=NetworkMode.PREVENT,
                block_threshold=3,
                domain_allowlist=["safe.com"],
            ),
            smtp_relay=SmtpRelaySettings(
                mode=NetworkMode.PREVENT,
                block_threshold=10,
            ),
        )
        data = r.model_dump()
        r2 = NetworkSettingsResponse(**data)
        assert r2.http_proxy.mode == NetworkMode.PREVENT
        assert r2.http_proxy.domain_allowlist == ["safe.com"]
        assert r2.smtp_relay.block_threshold == 10


# ---------------------------------------------------------------------------
# Persistence tests
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_load_returns_defaults_when_missing(self, tmp_path):
        fake_path = tmp_path / "nonexistent" / "settings.json"
        with patch("server.api.network_settings.SETTINGS_FILE", fake_path):
            result = _load_settings()
        assert result.http_proxy.mode == NetworkMode.MONITOR
        assert result.smtp_relay.mode == NetworkMode.MONITOR

    def test_save_and_load_roundtrip(self, tmp_path):
        fake_path = tmp_path / "data" / "settings.json"
        settings = NetworkSettingsResponse(
            http_proxy=HttpProxySettings(
                mode=NetworkMode.PREVENT,
                block_threshold=7,
                domain_allowlist=["example.com"],
            ),
        )
        with patch("server.api.network_settings.SETTINGS_FILE", fake_path):
            _save_settings(settings)
            loaded = _load_settings()

        assert loaded.http_proxy.mode == NetworkMode.PREVENT
        assert loaded.http_proxy.block_threshold == 7
        assert "example.com" in loaded.http_proxy.domain_allowlist

    def test_load_handles_corrupt_json(self, tmp_path):
        fake_path = tmp_path / "settings.json"
        fake_path.write_text("{corrupt json!!!")
        with patch("server.api.network_settings.SETTINGS_FILE", fake_path):
            result = _load_settings()
        assert result.http_proxy.mode == NetworkMode.MONITOR

    def test_save_creates_parent_directories(self, tmp_path):
        fake_path = tmp_path / "a" / "b" / "c" / "settings.json"
        with patch("server.api.network_settings.SETTINGS_FILE", fake_path):
            _save_settings(NetworkSettingsResponse())
        assert fake_path.exists()

    def test_partial_update_preserves_other_section(self, tmp_path):
        fake_path = tmp_path / "settings.json"
        initial = NetworkSettingsResponse(
            http_proxy=HttpProxySettings(mode=NetworkMode.PREVENT, block_threshold=5),
            smtp_relay=SmtpRelaySettings(mode=NetworkMode.PREVENT, block_threshold=10),
        )
        with patch("server.api.network_settings.SETTINGS_FILE", fake_path):
            _save_settings(initial)

            # Load, update only HTTP, save
            current = _load_settings()
            current.http_proxy = HttpProxySettings(mode=NetworkMode.MONITOR)
            _save_settings(current)

            reloaded = _load_settings()

        assert reloaded.http_proxy.mode == NetworkMode.MONITOR
        assert reloaded.smtp_relay.mode == NetworkMode.PREVENT
        assert reloaded.smtp_relay.block_threshold == 10
