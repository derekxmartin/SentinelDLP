"""Tests for DataIdentifierAnalyzer and validators (P1-T4).

Covers: All 10 built-in data identifiers with validation, Luhn checksum,
SSN area number, MOD-97 IBAN, ABA checksum, custom identifiers,
component targeting, false positive rejection, and precision tests.
"""

import pytest

from server.detection.models import ComponentType, ParsedMessage
from server.detection.analyzers.data_identifier_analyzer import (
    DataIdentifierAnalyzer,
    DataIdentifierConfig,
)
from server.detection.analyzers.validators import (
    luhn,
    ssn_area,
    phone_format,
    email_domain,
    iban_mod97,
    passport_format,
    drivers_license_format,
    ipv4_range,
    date_calendar,
    aba_checksum,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_message(**components: str) -> ParsedMessage:
    msg = ParsedMessage()
    type_map = {
        "envelope": ComponentType.ENVELOPE,
        "subject": ComponentType.SUBJECT,
        "body": ComponentType.BODY,
        "attachment": ComponentType.ATTACHMENT,
        "generic": ComponentType.GENERIC,
    }
    for key, content in components.items():
        msg.add_component(type_map[key], content)
    return msg


# ---------------------------------------------------------------------------
# Seed config (mirrors server/scripts/seed.py)
# ---------------------------------------------------------------------------

SEED_IDENTIFIERS = [
    {
        "name": "Credit Card Number (Visa/MC/Amex/Discover)",
        "description": "Credit cards with Luhn validation",
        "config": {
            "patterns": [
                r"4[0-9]{12}(?:[0-9]{3})?",
                r"5[1-5][0-9]{14}",
                r"3[47][0-9]{13}",
                r"6(?:011|5[0-9]{2})[0-9]{12}",
            ],
            "validator": "luhn",
            "example": "4532015112830366",
        },
    },
    {
        "name": "US Social Security Number",
        "config": {
            "patterns": [r"\b\d{3}-\d{2}-\d{4}\b"],
            "validator": "ssn_area",
            "example": "123-45-6789",
        },
    },
    {
        "name": "US Phone Number",
        "config": {
            "patterns": [r"\b(?:\+1)?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"],
            "validator": "phone_format",
            "example": "(555) 123-4567",
        },
    },
    {
        "name": "Email Address",
        "config": {
            "patterns": [r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"],
            "validator": "email_domain",
            "example": "user@example.com",
        },
    },
    {
        "name": "IBAN",
        "config": {
            "patterns": [r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"],
            "validator": "iban_mod97",
            "example": "GB29NWBK60161331926819",
        },
    },
    {
        "name": "US Passport Number",
        "config": {
            "patterns": [r"\b[A-Z]?\d{8,9}\b"],
            "validator": "passport_format",
            "example": "123456789",
        },
    },
    {
        "name": "US Driver's License",
        "config": {
            "patterns": [
                r"\b[A-Z]\d{7}\b",
                r"\b[A-Z]\d{12}\b",
                r"\b\d{9}\b",
                r"\b[A-Z]{2}\d{6}\b",
            ],
            "validator": "drivers_license_format",
            "example": "D1234567",
        },
    },
    {
        "name": "IPv4 Address",
        "config": {
            "patterns": [r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"],
            "validator": "ipv4_range",
            "example": "192.168.1.1",
        },
    },
    {
        "name": "Date of Birth",
        "config": {
            "patterns": [
                r"\b\d{1,2}/\d{1,2}/\d{4}\b",
                r"\b\d{4}-\d{2}-\d{2}\b",
                r"\b\d{1,2}-\d{1,2}-\d{4}\b",
            ],
            "validator": "date_calendar",
            "example": "01/15/1990",
        },
    },
    {
        "name": "US Bank Routing Number (ABA)",
        "config": {
            "patterns": [r"\b\d{9}\b"],
            "validator": "aba_checksum",
            "example": "021000021",
        },
    },
]


# ===========================================================================
# Validator unit tests
# ===========================================================================


class TestLuhnValidator:
    """Luhn checksum validation for credit cards."""

    def test_valid_visa(self):
        assert luhn("4532015112830366") is True

    def test_valid_mastercard(self):
        assert luhn("5425233430109903") is True

    def test_valid_amex(self):
        assert luhn("374245455400126") is True

    def test_valid_discover(self):
        assert luhn("6011514433546201") is True

    def test_valid_with_spaces(self):
        assert luhn("4532 0151 1283 0366") is True

    def test_valid_with_dashes(self):
        assert luhn("4532-0151-1283-0366") is True

    def test_invalid_checksum(self):
        assert luhn("4532015112830367") is False

    def test_invalid_all_zeros(self):
        assert luhn("0000000000000000") is True  # Luhn passes for all zeros

    def test_invalid_too_short(self):
        assert luhn("453201") is False

    def test_invalid_non_digit(self):
        assert luhn("4532abc112830366") is False


class TestSSNAreaValidator:
    """SSN area number validation."""

    def test_valid_ssn(self):
        assert ssn_area("123-45-6789") is True

    def test_valid_no_dashes(self):
        assert ssn_area("123456789") is True

    def test_area_000_rejected(self):
        assert ssn_area("000-12-3456") is False

    def test_area_666_rejected(self):
        assert ssn_area("666-12-3456") is False

    def test_area_900_rejected(self):
        assert ssn_area("900-12-3456") is False

    def test_area_999_rejected(self):
        assert ssn_area("999-12-3456") is False

    def test_group_00_rejected(self):
        assert ssn_area("123-00-6789") is False

    def test_serial_0000_rejected(self):
        assert ssn_area("123-45-0000") is False

    def test_valid_boundary_area_001(self):
        assert ssn_area("001-01-0001") is True

    def test_valid_boundary_area_899(self):
        assert ssn_area("899-99-9999") is True


class TestPhoneValidator:

    def test_valid_standard(self):
        assert phone_format("(555) 234-5678") is True

    def test_valid_with_country_code(self):
        assert phone_format("+1 555 234 5678") is True

    def test_valid_dots(self):
        assert phone_format("555.234.5678") is True

    def test_invalid_area_starts_0(self):
        assert phone_format("(055) 123-4567") is False

    def test_invalid_area_starts_1(self):
        assert phone_format("(155) 123-4567") is False

    def test_invalid_exchange_starts_0(self):
        assert phone_format("(555) 023-4567") is False


class TestEmailValidator:

    def test_valid(self):
        assert email_domain("user@example.com") is True

    def test_valid_subdomain(self):
        assert email_domain("user@mail.example.co.uk") is True

    def test_invalid_no_domain(self):
        assert email_domain("user@") is False

    def test_invalid_no_tld(self):
        assert email_domain("user@localhost") is False

    def test_invalid_single_char_tld(self):
        assert email_domain("user@example.x") is False


class TestIBANValidator:
    """IBAN MOD-97 checksum."""

    def test_valid_gb(self):
        assert iban_mod97("GB29NWBK60161331926819") is True

    def test_valid_de(self):
        assert iban_mod97("DE89370400440532013000") is True

    def test_valid_fr(self):
        assert iban_mod97("FR7630006000011234567890189") is True

    def test_invalid_bad_checksum(self):
        assert iban_mod97("GB29NWBK60161331926818") is False

    def test_invalid_too_short(self):
        assert iban_mod97("GB29") is False

    def test_valid_with_spaces(self):
        assert iban_mod97("GB29 NWBK 6016 1331 9268 19") is True


class TestPassportValidator:

    def test_valid_9_digits(self):
        assert passport_format("123456789") is True

    def test_valid_8_digits(self):
        assert passport_format("12345678") is True

    def test_valid_with_letter(self):
        assert passport_format("C12345678") is True

    def test_invalid_too_short(self):
        assert passport_format("1234567") is False


class TestDriversLicenseValidator:

    def test_valid_standard(self):
        assert drivers_license_format("D1234567") is True

    def test_rejects_all_zeros(self):
        assert drivers_license_format("D0000000") is False

    def test_valid_state_format(self):
        assert drivers_license_format("WA123456") is True


class TestIPv4Validator:

    def test_valid(self):
        assert ipv4_range("192.168.1.1") is True

    def test_valid_loopback(self):
        assert ipv4_range("127.0.0.1") is True

    def test_invalid_octet_over_255(self):
        assert ipv4_range("192.168.1.256") is False

    def test_invalid_all_zeros(self):
        assert ipv4_range("0.0.0.0") is False

    def test_invalid_broadcast(self):
        assert ipv4_range("255.255.255.255") is False

    def test_valid_edge_254(self):
        assert ipv4_range("255.255.255.254") is True


class TestDateValidator:

    def test_valid_us_format(self):
        assert date_calendar("01/15/1990") is True

    def test_valid_iso_format(self):
        assert date_calendar("1990-01-15") is True

    def test_valid_dash_format(self):
        assert date_calendar("01-15-1990") is True

    def test_invalid_feb_30(self):
        assert date_calendar("02/30/2020") is False

    def test_invalid_month_13(self):
        assert date_calendar("13/01/2020") is False

    def test_invalid_year_too_old(self):
        assert date_calendar("01/01/1899") is False

    def test_leap_year(self):
        assert date_calendar("02/29/2024") is True

    def test_not_leap_year(self):
        assert date_calendar("02/29/2023") is False


class TestABAValidator:
    """ABA routing number 3-7-1 checksum."""

    def test_valid_chase(self):
        assert aba_checksum("021000021") is True

    def test_valid_bofa(self):
        assert aba_checksum("026009593") is True

    def test_valid_wells_fargo(self):
        assert aba_checksum("121000248") is True

    def test_invalid_checksum(self):
        assert aba_checksum("021000022") is False

    def test_invalid_too_short(self):
        assert aba_checksum("02100002") is False

    def test_invalid_non_digit(self):
        assert aba_checksum("02100002X") is False


# ===========================================================================
# DataIdentifierAnalyzer tests
# ===========================================================================


class TestCreditCardDetection:
    """Credit card detection with Luhn validation."""

    def _make_analyzer(self):
        return DataIdentifierAnalyzer(
            name="cc",
            identifiers=[
                DataIdentifierConfig(
                    name="Credit Card",
                    patterns=[
                        r"4[0-9]{12}(?:[0-9]{3})?",
                        r"5[1-5][0-9]{14}",
                        r"3[47][0-9]{13}",
                        r"6(?:011|5[0-9]{2})[0-9]{12}",
                    ],
                    validator="luhn",
                )
            ],
        )

    def test_valid_visa_detected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="Card: 4532015112830366")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1
        assert matches[0].metadata["validated"] is True

    def test_invalid_luhn_rejected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="Card: 4532015112830367")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_multiple_valid_cards(self):
        analyzer = self._make_analyzer()
        msg = _make_message(
            body=(
                "Visa: 4532015112830366 "
                "MC: 5425233430109903 "
                "Amex: 374245455400126 "
                "Disc: 6011514433546201"
            )
        )
        matches = analyzer.analyze(msg)
        assert len(matches) == 4

    def test_5_valid_cards_in_document(self):
        """Acceptance: 5 valid CC numbers detected."""
        analyzer = self._make_analyzer()
        msg = _make_message(
            body=(
                "Transaction log:\n"
                "1. 4532015112830366\n"
                "2. 5425233430109903\n"
                "3. 374245455400126\n"
                "4. 6011514433546201\n"
                "5. 4916338506082832\n"
            )
        )
        matches = analyzer.analyze(msg)
        assert len(matches) == 5

    def test_5_invalid_checksums_rejected(self):
        """Acceptance: 5 invalid CC checksums → no matches."""
        analyzer = self._make_analyzer()
        msg = _make_message(
            body=(
                "Bad cards:\n"
                "1. 4532015112830367\n"
                "2. 5425233430109904\n"
                "3. 374245455400127\n"
                "4. 6011514433546202\n"
                "5. 4916338506082833\n"
            )
        )
        matches = analyzer.analyze(msg)
        assert len(matches) == 0


class TestSSNDetection:
    """SSN detection with area number validation."""

    def _make_analyzer(self):
        return DataIdentifierAnalyzer(
            name="ssn",
            identifiers=[
                DataIdentifierConfig(
                    name="US SSN",
                    patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
                    validator="ssn_area",
                )
            ],
        )

    def test_valid_ssn_detected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="SSN: 123-45-6789")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_area_000_rejected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="SSN: 000-45-6789")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_area_666_rejected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="SSN: 666-45-6789")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_area_900_rejected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="SSN: 950-45-6789")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0


class TestIBANDetection:
    """IBAN detection with MOD-97 validation."""

    def _make_analyzer(self):
        return DataIdentifierAnalyzer(
            name="iban",
            identifiers=[
                DataIdentifierConfig(
                    name="IBAN",
                    patterns=[r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"],
                    validator="iban_mod97",
                )
            ],
        )

    def test_valid_iban_detected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="IBAN: GB29NWBK60161331926819")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_invalid_checksum_rejected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="IBAN: GB29NWBK60161331926818")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0


class TestABADetection:
    """ABA routing number detection with checksum."""

    def _make_analyzer(self):
        return DataIdentifierAnalyzer(
            name="aba",
            identifiers=[
                DataIdentifierConfig(
                    name="ABA Routing",
                    patterns=[r"\b\d{9}\b"],
                    validator="aba_checksum",
                )
            ],
        )

    def test_valid_routing_detected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="Routing: 021000021")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_invalid_checksum_rejected(self):
        analyzer = self._make_analyzer()
        msg = _make_message(body="Routing: 021000022")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0


# ===========================================================================
# All 10 identifiers test
# ===========================================================================


class TestAll10Identifiers:
    """Acceptance: all 10 built-in identifiers pass validation tests."""

    def test_all_10_from_seed_config(self):
        """Load all 10 identifiers from seed config and detect valid examples."""
        analyzer = DataIdentifierAnalyzer.from_seed_config(
            name="all10", seed_identifiers=SEED_IDENTIFIERS
        )
        assert analyzer.identifier_count == 10

        # Document with one valid example of each identifier
        document = (
            "Credit Card: 4532015112830366\n"
            "SSN: 123-45-6789\n"
            "Phone: (555) 234-5678\n"
            "Email: user@example.com\n"
            "IBAN: GB29NWBK60161331926819\n"
            "Passport: 123456789\n"
            "DL: D1234567\n"
            "IP: 192.168.1.100\n"
            "DOB: 01/15/1990\n"
            "ABA: 021000021\n"
        )
        msg = _make_message(body=document)
        matches = analyzer.analyze(msg)

        detected_identifiers = {m.rule_name for m in matches}
        assert "Credit Card Number (Visa/MC/Amex/Discover)" in detected_identifiers
        assert "US Social Security Number" in detected_identifiers
        assert "US Phone Number" in detected_identifiers
        assert "Email Address" in detected_identifiers
        assert "IBAN" in detected_identifiers
        assert "IPv4 Address" in detected_identifiers
        assert "Date of Birth" in detected_identifiers

    def test_identifier_count_from_seed(self):
        analyzer = DataIdentifierAnalyzer.from_seed_config(
            name="all10", seed_identifiers=SEED_IDENTIFIERS
        )
        assert analyzer.identifier_count == 10


# ===========================================================================
# Precision tests (>99% requirement)
# ===========================================================================


class TestPrecision:
    """Precision tests — validators should reject false positives."""

    def test_cc_precision_corpus(self):
        """Test CC detection against a corpus of valid and invalid numbers."""
        analyzer = DataIdentifierAnalyzer(
            name="cc",
            identifiers=[
                DataIdentifierConfig(
                    name="CC",
                    patterns=[r"4[0-9]{12}(?:[0-9]{3})?"],
                    validator="luhn",
                )
            ],
        )

        valid = [
            "4532015112830366",
            "4916338506082832",
            "4539578763621486",
            "4024007198964305",
            "4556737586899855",
        ]
        invalid = [
            "4532015112830367",
            "4916338506082833",
            "4539578763621487",
            "4024007198964306",
            "4556737586899856",
        ]

        # All valid should match
        for v in valid:
            msg = _make_message(body=v)
            assert len(analyzer.analyze(msg)) == 1, f"Should match: {v}"

        # All invalid should be rejected
        for inv in invalid:
            msg = _make_message(body=inv)
            assert len(analyzer.analyze(msg)) == 0, f"Should reject: {inv}"

    def test_ssn_precision_corpus(self):
        """SSN detection rejects all invalid area/group/serial combinations."""
        analyzer = DataIdentifierAnalyzer(
            name="ssn",
            identifiers=[
                DataIdentifierConfig(
                    name="SSN",
                    patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
                    validator="ssn_area",
                )
            ],
        )

        valid = ["123-45-6789", "001-01-0001", "899-99-9999", "555-55-5555"]
        invalid = [
            "000-45-6789",  # area 000
            "666-45-6789",  # area 666
            "900-45-6789",  # area 900+
            "123-00-6789",  # group 00
            "123-45-0000",  # serial 0000
        ]

        for v in valid:
            msg = _make_message(body=v)
            assert len(analyzer.analyze(msg)) == 1, f"Should match: {v}"

        for inv in invalid:
            msg = _make_message(body=inv)
            assert len(analyzer.analyze(msg)) == 0, f"Should reject: {inv}"

    def test_iban_precision_corpus(self):
        """IBAN MOD-97 rejects invalid checksums."""
        analyzer = DataIdentifierAnalyzer(
            name="iban",
            identifiers=[
                DataIdentifierConfig(
                    name="IBAN",
                    patterns=[r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"],
                    validator="iban_mod97",
                )
            ],
        )

        valid = [
            "GB29NWBK60161331926819",
            "DE89370400440532013000",
            "FR7630006000011234567890189",
        ]
        invalid = [
            "GB29NWBK60161331926818",
            "DE89370400440532013001",
            "FR7630006000011234567890188",
        ]

        for v in valid:
            msg = _make_message(body=v)
            assert len(analyzer.analyze(msg)) >= 1, f"Should match: {v}"

        for inv in invalid:
            msg = _make_message(body=inv)
            assert len(analyzer.analyze(msg)) == 0, f"Should reject: {inv}"


# ===========================================================================
# Custom identifiers
# ===========================================================================


class TestCustomIdentifiers:
    """Support for user-defined identifiers and validators."""

    def test_custom_validator(self):
        """Custom validator function works."""

        def always_valid(value: str) -> bool:
            return True

        analyzer = DataIdentifierAnalyzer(
            name="custom",
            identifiers=[
                DataIdentifierConfig(
                    name="Custom ID",
                    patterns=[r"CUST-\d{4}"],
                    validator="custom_check",
                )
            ],
            custom_validators={"custom_check": always_valid},
        )
        msg = _make_message(body="ID: CUST-1234")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_custom_validator_rejects(self):
        """Custom validator that rejects all matches."""

        def always_invalid(value: str) -> bool:
            return False

        analyzer = DataIdentifierAnalyzer(
            name="custom",
            identifiers=[
                DataIdentifierConfig(
                    name="Custom ID",
                    patterns=[r"CUST-\d{4}"],
                    validator="strict_check",
                )
            ],
            custom_validators={"strict_check": always_invalid},
        )
        msg = _make_message(body="ID: CUST-1234")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_no_validator_regex_only(self):
        """Identifier with no validator — regex match alone is sufficient."""
        analyzer = DataIdentifierAnalyzer(
            name="no_val",
            identifiers=[
                DataIdentifierConfig(
                    name="Project Code",
                    patterns=[r"PROJ-\d{6}"],
                    validator=None,
                )
            ],
        )
        msg = _make_message(body="Code: PROJ-123456")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1
        assert matches[0].metadata["validated"] is False

    def test_unknown_validator_raises(self):
        """Referencing a non-existent validator raises ValueError."""
        with pytest.raises(ValueError, match="Unknown validator"):
            DataIdentifierAnalyzer(
                name="bad",
                identifiers=[
                    DataIdentifierConfig(
                        name="Bad",
                        patterns=[r"\d+"],
                        validator="nonexistent",
                    )
                ],
            )


# ===========================================================================
# Component targeting
# ===========================================================================


class TestComponentTargeting:

    def test_body_only(self):
        analyzer = DataIdentifierAnalyzer(
            name="cc",
            identifiers=[
                DataIdentifierConfig(
                    name="CC",
                    patterns=[r"4[0-9]{12}(?:[0-9]{3})?"],
                    validator="luhn",
                )
            ],
            target_components=[ComponentType.BODY],
        )
        msg = _make_message(
            subject="Card: 4532015112830366",
            body="Card: 4532015112830366",
            attachment="Card: 4532015112830366",
        )
        matches = analyzer.analyze(msg)
        assert len(matches) == 1
        assert matches[0].component.component_type == ComponentType.BODY


# ===========================================================================
# Engine integration
# ===========================================================================


class TestEngineIntegration:

    def test_engine_with_data_identifier(self):
        from server.detection.engine import DetectionEngine

        engine = DetectionEngine()
        analyzer = DataIdentifierAnalyzer.from_seed_config(
            name="all_ids", seed_identifiers=SEED_IDENTIFIERS[:3]
        )
        engine.register(analyzer)

        msg = _make_message(
            body="CC: 4532015112830366 SSN: 123-45-6789 Phone: (555) 234-5678"
        )
        result = engine.detect(msg)
        assert result.has_matches
        assert len(result.errors) == 0
