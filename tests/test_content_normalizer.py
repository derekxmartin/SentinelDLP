"""Tests for AkesoDLP Content Normalizer.

Tests iterative decoding of URL encoding, base64, and HTML entities
with depth limits to resist multi-layer encoding evasion.
"""

from __future__ import annotations

import base64
from urllib.parse import quote

import pytest

from network.content_normalizer import normalize, _url_decode, _html_entity_decode, _base64_decode_embedded


# ================================================================== #
#  URL decoding                                                        #
# ================================================================== #


class TestURLDecode:
    def test_basic_percent_encoding(self) -> None:
        assert _url_decode("SSN%3A%20123-45-6789") == "SSN: 123-45-6789"

    def test_no_encoding(self) -> None:
        text = "plain text no encoding"
        assert _url_decode(text) == text

    def test_double_encoded(self) -> None:
        # Single pass: %2520 -> %20 (not fully decoded)
        assert _url_decode("SSN%253A%2520123-45-6789") == "SSN%3A%20123-45-6789"

    def test_utf8_sequences(self) -> None:
        # URL-encoded UTF-8 for "hello"
        assert _url_decode("hello%20world") == "hello world"

    def test_plus_not_decoded(self) -> None:
        # unquote does NOT decode + as space (that's unquote_plus)
        assert _url_decode("hello+world") == "hello+world"


# ================================================================== #
#  HTML entity decoding                                                #
# ================================================================== #


class TestHTMLEntityDecode:
    def test_numeric_entities(self) -> None:
        assert _html_entity_decode("&#49;&#50;&#51;") == "123"

    def test_hex_entities(self) -> None:
        assert _html_entity_decode("&#x31;&#x32;&#x33;") == "123"

    def test_named_entities(self) -> None:
        assert _html_entity_decode("&lt;script&gt;") == "<script>"

    def test_no_entities(self) -> None:
        text = "no entities here"
        assert _html_entity_decode(text) == text

    def test_mixed_entities(self) -> None:
        assert _html_entity_decode("SSN: &#49;23-&#52;5-&#54;789") == "SSN: 123-45-6789"

    def test_ampersand_without_entity(self) -> None:
        # Bare & not followed by valid entity should be left alone
        result = _html_entity_decode("AT&T")
        assert "AT" in result and "T" in result


# ================================================================== #
#  Base64 decoding                                                     #
# ================================================================== #


class TestBase64Decode:
    def test_embedded_base64(self) -> None:
        ssn_b64 = base64.b64encode(b"SSN: 123-45-6789").decode()
        # ssn_b64 is "U1NOOiAxMjMtNDUtNjc4OQ==" (24 chars, below threshold)
        # Need to pad to meet _MIN_B64_LENGTH of 32
        payload = base64.b64encode(b"Sensitive data: SSN is 123-45-6789 and more").decode()
        result = _base64_decode_embedded(f"data={payload}")
        assert "123-45-6789" in result

    def test_short_b64_ignored(self) -> None:
        # Short base64 strings should not be decoded (false positive risk)
        result = _base64_decode_embedded("token=abc123")
        assert result == "token=abc123"

    def test_binary_b64_not_decoded(self) -> None:
        # Base64 that decodes to binary (non-printable) should be left alone
        binary_data = bytes(range(256))
        b64 = base64.b64encode(binary_data).decode()
        result = _base64_decode_embedded(b64)
        # Should be left unchanged because decoded content is mostly non-printable
        assert result == b64

    def test_no_b64_content(self) -> None:
        text = "just regular text with no base64"
        assert _base64_decode_embedded(text) == text


# ================================================================== #
#  Iterative normalization                                             #
# ================================================================== #


class TestNormalize:
    def test_single_url_decode(self) -> None:
        variants = normalize("SSN%3A%20123-45-6789")
        assert any("SSN: 123-45-6789" in v for v in variants)

    def test_double_url_decode(self) -> None:
        # %253A -> %3A -> :
        # %2520 -> %20 -> (space)
        encoded = quote(quote("SSN: 123-45-6789"))
        variants = normalize(encoded)
        assert any("SSN: 123-45-6789" in v for v in variants)

    def test_triple_url_decode(self) -> None:
        encoded = quote(quote(quote("SSN: 123-45-6789")))
        variants = normalize(encoded)
        assert any("SSN: 123-45-6789" in v for v in variants)

    def test_html_entity_decode(self) -> None:
        encoded = "SSN: &#49;&#50;&#51;-&#52;&#53;-&#54;&#55;&#56;&#57;"
        variants = normalize(encoded)
        assert any("123-45-6789" in v for v in variants)

    def test_base64_then_url_encode(self) -> None:
        """Base64-encoded SSN, then URL-encoded. Two layers."""
        b64 = base64.b64encode(b"Sensitive: SSN is 123-45-6789 in this document").decode()
        url_encoded = quote(b64)
        variants = normalize(url_encoded)
        # After URL decode: b64 string. After b64 decode: original text.
        assert any("123-45-6789" in v for v in variants)

    def test_original_always_included(self) -> None:
        text = "original text"
        variants = normalize(text)
        assert variants[0] == text

    def test_no_encoding_returns_original_only(self) -> None:
        text = "plain text nothing to decode"
        variants = normalize(text)
        assert len(variants) == 1
        assert variants[0] == text

    def test_max_depth_respected(self) -> None:
        # 10 layers of URL encoding — only 5 should be decoded
        text = "SSN: 123-45-6789"
        encoded = text
        for _ in range(10):
            encoded = quote(encoded)
        variants = normalize(encoded, max_depth=5)
        # With depth 5, we decode 5 layers out of 10
        # The fully decoded version should NOT be present
        assert len(variants) <= 6  # original + up to 5 decoded

    def test_depth_zero_returns_original(self) -> None:
        variants = normalize("SSN%3A%20123-45-6789", max_depth=0)
        assert len(variants) == 1
        assert "SSN%3A" in variants[0]

    def test_stabilization(self) -> None:
        """Single layer of encoding — should decode and stop."""
        text = "SSN%3A%20123-45-6789"
        variants = normalize(text)
        # Should have original + decoded
        assert len(variants) == 2
        assert variants[0] == text
        assert variants[1] == "SSN: 123-45-6789"

    def test_idempotent_on_clean_text(self) -> None:
        """Clean text should produce exactly one variant."""
        for text in ["hello", "123-45-6789", "no encoding here", ""]:
            variants = normalize(text)
            assert len(variants) == 1


# ================================================================== #
#  Multi-layer evasion scenarios                                       #
# ================================================================== #


class TestMultiLayerEvasion:
    def test_3x_base64(self) -> None:
        """Triple base64 encoding — the defender's concern."""
        payload = b"SSN: 123-45-6789 is the sensitive data here"
        encoded = base64.b64encode(payload).decode()
        encoded = base64.b64encode(encoded.encode()).decode()
        encoded = base64.b64encode(encoded.encode()).decode()
        variants = normalize(encoded)
        assert any("123-45-6789" in v for v in variants)

    def test_url_then_b64_then_url(self) -> None:
        """URL encode → base64 → URL encode. Mixed layers."""
        text = "SSN: 123-45-6789 is sensitive data in this payload"
        layer1 = quote(text)
        layer2 = base64.b64encode(layer1.encode()).decode()
        layer3 = quote(layer2)
        variants = normalize(layer3)
        assert any("123-45-6789" in v for v in variants)

    def test_html_then_url(self) -> None:
        """HTML entity encode → URL encode."""
        html_encoded = "SSN: &#49;&#50;&#51;-&#52;&#53;-&#54;&#55;&#56;&#57;"
        url_encoded = quote(html_encoded)
        variants = normalize(url_encoded)
        assert any("123-45-6789" in v for v in variants)

    def test_5x_url_encode(self) -> None:
        """Five layers of URL encoding — all should be decoded."""
        text = "SSN: 123-45-6789"
        encoded = text
        for _ in range(5):
            encoded = quote(encoded)
        variants = normalize(encoded, max_depth=5)
        assert any("SSN: 123-45-6789" in v for v in variants)

    def test_6x_url_encode_partial(self) -> None:
        """Six layers, max_depth=5 — one layer remains encoded."""
        text = "SSN: 123-45-6789"
        encoded = text
        for _ in range(6):
            encoded = quote(encoded)
        variants = normalize(encoded, max_depth=5)
        # Fully decoded should NOT be present — still one layer remaining
        fully_decoded_found = any(v == text for v in variants)
        assert not fully_decoded_found
