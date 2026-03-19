"""AkesoDLP Content Normalizer — iterative decode for evasion resistance.

Applies multiple decoding passes (URL decode, base64, HTML entities)
in a loop until content stabilizes or a depth limit is reached.
This closes the HTTP evasion gap where attackers can wrap sensitive
content in one or more encoding layers.

Design decisions:
  - Max decode depth of 5 (configurable). Sufficient for realistic
    evasion while bounding CPU cost on adversarial input.
  - Each pass applies all decoders in sequence. If ANY decoder changes
    the content, another pass is triggered (up to the depth limit).
  - Base64 detection is conservative: requires 32+ chars of valid
    base64 alphabet to avoid false positives on normal text.
  - The original (unnormalized) text is always scanned too — normalization
    produces ADDITIONAL text variants, it doesn't replace the original.
"""

from __future__ import annotations

import base64
import html
import logging
import re
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# Minimum length of a base64-looking string to attempt decode.
# Short strings produce too many false positives.
_MIN_B64_LENGTH = 32

# Pattern for plausible base64 strings: [A-Za-z0-9+/=] with optional
# whitespace, at least _MIN_B64_LENGTH chars of actual b64 content.
_B64_PATTERN = re.compile(
    r"[A-Za-z0-9+/]{" + str(_MIN_B64_LENGTH) + r",}={0,2}"
)


def normalize(text: str, max_depth: int = 5) -> list[str]:
    """Produce normalized variants of the input text.

    Iteratively applies URL decoding, HTML entity decoding, and base64
    decoding until the text stabilizes or max_depth is reached.

    Args:
        text: The raw text to normalize.
        max_depth: Maximum number of decode passes.

    Returns:
        List of unique text variants (always includes the original).
        The original is first, followed by any decoded variants.
    """
    variants: list[str] = [text]
    seen: set[str] = {text}
    current = text

    for depth in range(max_depth):
        decoded = _decode_pass(current)
        if decoded == current:
            break  # Content stabilized
        if decoded not in seen:
            variants.append(decoded)
            seen.add(decoded)
        current = decoded

    return variants


def _decode_pass(text: str) -> str:
    """Apply one round of all decoders in sequence."""
    result = text
    result = _url_decode(result)
    result = _html_entity_decode(result)
    result = _base64_decode_embedded(result)
    return result


def _url_decode(text: str) -> str:
    """URL-decode percent-encoded sequences (%XX).

    Only decodes if the text contains percent-encoded characters.
    Uses stdlib urllib.parse.unquote which handles UTF-8 sequences.
    """
    if "%" not in text:
        return text
    try:
        return unquote(text)
    except Exception:
        return text


def _html_entity_decode(text: str) -> str:
    """Decode HTML entities (&amp; &#123; &#x7B; etc).

    Only decodes if the text contains '&' followed by '#' or alpha.
    """
    if "&" not in text:
        return text
    try:
        return html.unescape(text)
    except Exception:
        return text


def _base64_decode_embedded(text: str) -> str:
    """Find and decode base64-encoded substrings within the text.

    Replaces each base64 blob with its decoded UTF-8 text.
    Non-decodable blobs or binary results are left unchanged.
    """
    def _try_decode(match: re.Match) -> str:
        b64_str = match.group(0)
        try:
            # Pad if necessary
            padded = b64_str + "=" * (-len(b64_str) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
            # Only replace if the result looks like text (mostly printable)
            decoded_text = decoded_bytes.decode("utf-8", errors="strict")
            printable_ratio = sum(
                1 for c in decoded_text if c.isprintable() or c in "\n\r\t"
            ) / max(len(decoded_text), 1)
            if printable_ratio >= 0.8:
                return decoded_text
        except Exception:
            pass
        return b64_str  # leave unchanged

    return _B64_PATTERN.sub(_try_decode, text)
