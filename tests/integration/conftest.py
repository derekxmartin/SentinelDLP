"""Shared fixtures for integration tests.

All tests run against the live Docker server (http://localhost:8000).
Ensure `docker compose up server` is running before executing.
"""

from __future__ import annotations

import os

import httpx
import pytest

BASE_URL = os.getenv("DLP_TEST_URL", "http://localhost:8000")
ADMIN_USER = os.getenv("DLP_TEST_USER", "admin")
ADMIN_PASS = os.getenv("DLP_TEST_PASS", "AkesoDLP2026!")


@pytest.fixture(scope="session")
def base_url() -> str:
    return BASE_URL


@pytest.fixture(scope="session")
def admin_token(base_url: str) -> str:
    """Authenticate as admin and return the access token."""
    resp = httpx.post(
        f"{base_url}/api/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


@pytest.fixture(scope="session")
def auth_headers(admin_token: str) -> dict[str, str]:
    """Authorization headers for authenticated API calls."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="session")
def client(base_url: str, auth_headers: dict[str, str]) -> httpx.Client:
    """Pre-configured HTTP client with auth."""
    return httpx.Client(
        base_url=base_url,
        headers=auth_headers,
        timeout=30.0,
    )
