"""MFA service — TOTP enrollment, verification, and management.

Uses pyotp for TOTP generation and verification. Supports enrollment
flow: generate secret → verify code → enable MFA.
"""

from __future__ import annotations

import logging

import pyotp

logger = logging.getLogger(__name__)


def generate_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()


def get_provisioning_uri(
    secret: str, username: str, issuer: str = "AkesoDLP"
) -> str:
    """Generate an otpauth:// URI for QR code enrollment."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against a secret.

    Allows a 30-second window of tolerance (valid_window=1).
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
