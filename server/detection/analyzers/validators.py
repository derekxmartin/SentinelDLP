"""Validation functions for data identifiers.

Each validator takes a matched string and returns True if it passes
secondary validation (e.g., Luhn checksum for credit cards). This
reduces false positives from regex-only matching.
"""

from __future__ import annotations

import re
from datetime import datetime


def luhn(value: str) -> bool:
    """Luhn checksum validation for credit card numbers.

    Strips spaces and dashes, then applies the Luhn algorithm.
    Returns True if the checksum is valid.
    """
    digits = re.sub(r"[\s-]", "", value)
    if not digits.isdigit() or len(digits) < 13:
        return False

    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def ssn_area(value: str) -> bool:
    """SSN area number validation.

    Rejects SSNs with:
    - Area number 000
    - Area number 666
    - Area number 900-999
    - Group number 00
    - Serial number 0000
    """
    digits = re.sub(r"[\s-]", "", value)
    if not digits.isdigit() or len(digits) != 9:
        return False

    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])

    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0:
        return False
    if serial == 0:
        return False

    return True


def phone_format(value: str) -> bool:
    """US phone number format validation.

    Rejects numbers where area code or exchange starts with 0 or 1.
    """
    digits = re.sub(r"[^\d]", "", value)
    # Strip country code if present
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        return False

    area = int(digits[:3])
    exchange = int(digits[3:6])

    # Area code and exchange cannot start with 0 or 1
    if area < 200 or exchange < 200:
        return False

    return True


def email_domain(value: str) -> bool:
    """Email address basic validation.

    Checks that the domain part has at least one dot and valid TLD length.
    """
    if "@" not in value:
        return False

    local, domain = value.rsplit("@", 1)
    if not local or not domain:
        return False

    parts = domain.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]
    if len(tld) < 2 or len(tld) > 63:
        return False

    return True


def iban_mod97(value: str) -> bool:
    """IBAN MOD-97 checksum validation per ISO 13616.

    1. Move the first 4 characters to the end
    2. Convert letters to numbers (A=10, B=11, ..., Z=35)
    3. Compute modulo 97 — result must be 1
    """
    clean = re.sub(r"\s", "", value).upper()
    if len(clean) < 5 or len(clean) > 34:
        return False

    # Must start with 2 letters + 2 digits
    if not clean[:2].isalpha() or not clean[2:4].isdigit():
        return False

    # Rearrange: move first 4 chars to end
    rearranged = clean[4:] + clean[:4]

    # Convert to numeric string
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False

    return int(numeric) % 97 == 1


def passport_format(value: str) -> bool:
    """US passport number format validation.

    Must be 8-9 digits, optionally prefixed by a letter.
    """
    clean = value.strip()
    if clean and clean[0].isalpha():
        clean = clean[1:]
    return clean.isdigit() and 8 <= len(clean) <= 9


def drivers_license_format(value: str) -> bool:
    """US driver's license basic format validation.

    Accepts common state formats. Already filtered by regex patterns.
    """
    clean = value.strip()
    if not clean:
        return False
    # Already pattern-matched, just ensure it's not all zeros
    digits = re.sub(r"[^0-9]", "", clean)
    if digits and all(d == "0" for d in digits):
        return False
    return True


def ipv4_range(value: str) -> bool:
    """IPv4 address octet range validation.

    Each octet must be 0-255. Rejects common non-addresses:
    - 0.0.0.0
    - 255.255.255.255 (broadcast)
    """
    parts = value.split(".")
    if len(parts) != 4:
        return False

    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    for o in octets:
        if o < 0 or o > 255:
            return False

    # Reject 0.0.0.0 and broadcast
    if all(o == 0 for o in octets):
        return False
    if all(o == 255 for o in octets):
        return False

    return True


def date_calendar(value: str) -> bool:
    """Date validation against calendar.

    Supports: MM/DD/YYYY, YYYY-MM-DD, MM-DD-YYYY.
    Rejects invalid dates (e.g., Feb 30).
    Year must be between 1900 and 2100.
    """
    formats = [
        ("%m/%d/%Y", None),
        ("%Y-%m-%d", None),
        ("%m-%d-%Y", None),
    ]

    for fmt, _ in formats:
        try:
            dt = datetime.strptime(value.strip(), fmt)
            if 1900 <= dt.year <= 2100:
                return True
        except ValueError:
            continue

    return False


def aba_checksum(value: str) -> bool:
    """ABA routing number 3-7-1 weighted checksum validation.

    Algorithm: 3*d1 + 7*d2 + 1*d3 + 3*d4 + 7*d5 + 1*d6 + 3*d7 + 7*d8 + 1*d9
    Result must be divisible by 10.
    """
    digits = re.sub(r"\s", "", value)
    if not digits.isdigit() or len(digits) != 9:
        return False

    d = [int(c) for c in digits]
    weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    total = sum(d[i] * weights[i] for i in range(9))

    return total % 10 == 0


# Registry mapping validator names to functions
VALIDATORS: dict[str, callable] = {
    "luhn": luhn,
    "ssn_area": ssn_area,
    "phone_format": phone_format,
    "email_domain": email_domain,
    "iban_mod97": iban_mod97,
    "passport_format": passport_format,
    "drivers_license_format": drivers_license_format,
    "ipv4_range": ipv4_range,
    "date_calendar": date_calendar,
    "aba_checksum": aba_checksum,
}
