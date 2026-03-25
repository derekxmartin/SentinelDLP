"""P10-T4: Detection parity test.

Runs 100 test inputs through the Python server detection engine
and verifies consistent results. The C++ agent uses the same regex
patterns via Hyperscan, so this validates the canonical detection
behavior that the agent must match.

Categories tested:
  - Credit card numbers (valid Luhn + invalid)
  - Social Security Numbers (valid + near-miss)
  - Email addresses with sensitive content
  - Compound rules (multiple identifiers)
  - Edge cases (empty, Unicode, very long strings)
  - Severity tiers (HIGH, MEDIUM, LOW, INFO)
  - Exception/allowlist patterns
"""

from __future__ import annotations

import httpx
import pytest


# ---------------------------------------------------------------------------
# 100 test inputs with expected detection outcomes
# ---------------------------------------------------------------------------

TEST_INPUTS = [
    # --- Credit Cards (should detect) ---
    {"text": "Pay with 4111111111111111", "expect_match": True, "id": "cc-visa-1"},
    {"text": "Card: 5500000000000004", "expect_match": True, "id": "cc-mc-1"},
    {"text": "AMEX 378282246310005", "expect_match": True, "id": "cc-amex-1"},
    {"text": "Multiple: 4111111111111111 and 5500000000000004", "expect_match": True, "id": "cc-multi"},
    {"text": "Visa ending 4111-1111-1111-1111", "expect_match": True, "id": "cc-dashed"},
    {"text": "CC 4222222222222", "expect_match": True, "id": "cc-visa-13digit"},
    {"text": "MasterCard 5105105105105100", "expect_match": True, "id": "cc-mc-2"},
    {"text": "Discover 6011111111111117", "expect_match": True, "id": "cc-discover"},
    {"text": "Card stored: 4012888888881881", "expect_match": True, "id": "cc-visa-3"},
    {"text": "Payment token 4000056655665556", "expect_match": True, "id": "cc-visa-4"},

    # --- Credit Cards (should NOT detect — invalid Luhn) ---
    {"text": "Not a card: 4111111111111112", "expect_match": False, "id": "cc-invalid-luhn"},
    {"text": "Random numbers: 1234567890123456", "expect_match": False, "id": "cc-random"},
    {"text": "Phone: 4111111111", "expect_match": False, "id": "cc-too-short"},
    {"text": "ID: 41111111111111111111", "expect_match": False, "id": "cc-too-long"},
    {"text": "Zeros: 0000000000000000", "expect_match": False, "id": "cc-all-zeros"},

    # --- SSN (should detect) ---
    {"text": "SSN: 123-45-6789", "expect_match": True, "id": "ssn-standard"},
    {"text": "Social: 987-65-4321", "expect_match": True, "id": "ssn-2"},
    {"text": "Employee SSN 078-05-1120", "expect_match": True, "id": "ssn-3"},
    {"text": "Tax ID: 219-09-9999", "expect_match": True, "id": "ssn-4"},
    {"text": "Multiple SSNs: 123-45-6789 and 987-65-4321", "expect_match": True, "id": "ssn-multi"},
    {"text": "SSN without dashes 123456789", "expect_match": True, "id": "ssn-no-dash"},
    {"text": "Formatted: 123 45 6789", "expect_match": True, "id": "ssn-spaces"},
    {"text": "Patient SSN: 321-54-9876", "expect_match": True, "id": "ssn-patient"},
    {"text": "Applicant SSN: 456-78-9012", "expect_match": True, "id": "ssn-applicant"},
    {"text": "W-2 form SSN: 111-22-3333", "expect_match": True, "id": "ssn-w2"},

    # --- SSN (should NOT detect) ---
    {"text": "Phone: 123-456-7890", "expect_match": False, "id": "ssn-phone"},
    {"text": "ZIP+4: 12345-6789", "expect_match": False, "id": "ssn-zip"},
    {"text": "Invalid area: 000-45-6789", "expect_match": False, "id": "ssn-invalid-area"},
    {"text": "Invalid group: 123-00-6789", "expect_match": False, "id": "ssn-invalid-group"},
    {"text": "Date: 12/34/5678", "expect_match": False, "id": "ssn-date"},

    # --- Email with sensitive content ---
    {"text": "Email to: cfo@company.com Re: Q4 financials", "expect_match": False, "id": "email-clean"},
    {"text": "Send payment details 4111111111111111 to billing@corp.com", "expect_match": True, "id": "email-with-cc"},
    {"text": "HR: SSN 123-45-6789 for new hire paperwork", "expect_match": True, "id": "email-with-ssn"},

    # --- Clean text (no matches) ---
    {"text": "The quick brown fox jumps over the lazy dog.", "expect_match": False, "id": "clean-1"},
    {"text": "Meeting at 3pm in Conference Room B.", "expect_match": False, "id": "clean-2"},
    {"text": "Please review the attached proposal and provide feedback.", "expect_match": False, "id": "clean-3"},
    {"text": "Q4 revenue increased 15% year-over-year.", "expect_match": False, "id": "clean-4"},
    {"text": "The server is running on port 8080.", "expect_match": False, "id": "clean-5"},
    {"text": "Updated the README with installation instructions.", "expect_match": False, "id": "clean-6"},
    {"text": "Sprint retrospective notes from last week.", "expect_match": False, "id": "clean-7"},
    {"text": "Budget allocation for FY2026 marketing campaigns.", "expect_match": False, "id": "clean-8"},
    {"text": "Employee handbook section 4.2: PTO policy.", "expect_match": False, "id": "clean-9"},
    {"text": "Architecture diagram for the microservices migration.", "expect_match": False, "id": "clean-10"},

    # --- Mixed content ---
    {"text": "Invoice #12345 for $50,000 - pay to account ending 4111111111111111", "expect_match": True, "id": "mixed-invoice"},
    {"text": "HR file: Name: Jane Doe, SSN: 234-56-7890, Salary: $85,000", "expect_match": True, "id": "mixed-hr"},
    {"text": "Tax return SSN 345-67-8901, AGI $120,000, refund $3,200", "expect_match": True, "id": "mixed-tax"},
    {"text": "Insurance claim: Policy #ABC123, Member SSN 456-78-9012", "expect_match": True, "id": "mixed-insurance"},

    # --- Edge cases ---
    {"text": "", "expect_match": False, "id": "edge-empty"},
    {"text": "a" * 10_000, "expect_match": False, "id": "edge-long-clean"},
    {"text": "Unicode: café résumé naïve SSN: 567-89-0123", "expect_match": True, "id": "edge-unicode"},
    {"text": "CC in URL: https://pay.com?card=4111111111111111", "expect_match": True, "id": "edge-url"},
    {"text": "Newlines:\n4111111111111111\n", "expect_match": True, "id": "edge-newlines"},
    {"text": "Tabs:\t4111111111111111\t", "expect_match": True, "id": "edge-tabs"},
    {"text": "   4111111111111111   ", "expect_match": True, "id": "edge-whitespace"},
    {"text": "CARD:4111111111111111.", "expect_match": True, "id": "edge-punctuation"},
    {"text": "SSN=123-45-6789;", "expect_match": True, "id": "edge-ssn-semicolon"},
    {"text": "null", "expect_match": False, "id": "edge-null-string"},

    # --- Boundary patterns ---
    {"text": "x4111111111111111x", "expect_match": False, "id": "boundary-no-word-break"},
    {"text": "ref:4111111111111111:end", "expect_match": True, "id": "boundary-colon-delim"},
    {"text": "(4111111111111111)", "expect_match": True, "id": "boundary-parens"},
    {"text": "[SSN: 678-90-1234]", "expect_match": True, "id": "boundary-brackets"},
    {"text": "\"4111111111111111\"", "expect_match": True, "id": "boundary-quotes"},

    # --- Severity tier inputs ---
    {"text": "CRITICAL: PCI data 4111111111111111 exfiltrated to USB", "expect_match": True, "id": "severity-critical"},
    {"text": "HIGH: Patient SSN 789-01-2345 found on public share", "expect_match": True, "id": "severity-high"},
    {"text": "MEDIUM: Email contains financial projections", "expect_match": False, "id": "severity-medium-no-pii"},
    {"text": "LOW: User accessed sensitive folder /hr/personnel", "expect_match": False, "id": "severity-low-no-data"},
    {"text": "INFO: Scheduled scan completed on 50 files", "expect_match": False, "id": "severity-info"},

    # --- Compound patterns ---
    {"text": "Name: John Smith, CC: 4111111111111111, SSN: 890-12-3456", "expect_match": True, "id": "compound-cc-ssn"},
    {"text": "Patient Jane Doe SSN 901-23-4567 Visa 4012888888881881", "expect_match": True, "id": "compound-ssn-cc"},
    {"text": "Account 4111111111111111 holder SSN 012-34-5678 DOB 01/01/1990", "expect_match": True, "id": "compound-all"},

    # --- Repeated patterns ---
    {"text": "CC: 4111111111111111 " * 10, "expect_match": True, "id": "repeated-cc"},
    {"text": "SSN: 123-45-6789 " * 5, "expect_match": True, "id": "repeated-ssn"},

    # --- Format variations ---
    {"text": "Visa: 4111 1111 1111 1111", "expect_match": True, "id": "format-cc-spaces"},
    {"text": "MC: 5500-0000-0000-0004", "expect_match": True, "id": "format-cc-dashes"},
    {"text": "SSN: 123.45.6789", "expect_match": True, "id": "format-ssn-dots"},

    # --- Near-miss (should NOT match) ---
    {"text": "Order #4111111111111111a (alphanumeric)", "expect_match": False, "id": "nearmiss-alpha"},
    {"text": "Version 1.2.3.4.5.6.7.8.9", "expect_match": False, "id": "nearmiss-version"},
    {"text": "IP: 123.45.67.89", "expect_match": False, "id": "nearmiss-ip"},
    {"text": "Timestamp: 20261234567890", "expect_match": False, "id": "nearmiss-timestamp"},
    {"text": "Part number: MC-5500-0000-0000-0004-REV-A", "expect_match": False, "id": "nearmiss-partnum"},

    # --- Allowlist/exception patterns ---
    {"text": "Test card 4111111111111111 for sandbox environment", "expect_match": True, "id": "allowlist-test-card"},
    {"text": "Synthetic SSN for testing: 987-65-4321", "expect_match": True, "id": "allowlist-test-ssn"},

    # --- Large content ---
    {"text": "Lorem ipsum " * 500 + " hidden CC 4111111111111111 " + "dolor sit " * 500, "expect_match": True, "id": "large-hidden-cc"},
    {"text": "Normal text " * 1000, "expect_match": False, "id": "large-clean"},

    # --- Fill to 100 ---
    {"text": "Transfer $10,000 to account 4917610000000000", "expect_match": True, "id": "cc-visa-electron"},
    {"text": "Wire SSN 234-56-7890 confirmation", "expect_match": True, "id": "ssn-wire"},
    {"text": "Benefits enrollment SSN: 345-67-8901", "expect_match": True, "id": "ssn-benefits"},
    {"text": "Direct deposit setup CC 5105105105105100", "expect_match": True, "id": "cc-direct-deposit"},
    {"text": "Contractor payment Visa 4222222222222", "expect_match": True, "id": "cc-contractor"},
    {"text": "Annual review - no sensitive data here", "expect_match": False, "id": "clean-review"},
    {"text": "Product roadmap Q3 2026 priorities", "expect_match": False, "id": "clean-roadmap"},
    {"text": "Routing number 021000021 for wire transfer", "expect_match": False, "id": "clean-routing"},
    {"text": "Employee badge #4111 access granted", "expect_match": False, "id": "clean-badge"},
    {"text": "SSN on new line:\n567-89-0123\nend", "expect_match": True, "id": "ssn-newline"},
    {"text": "Two cards: 4111111111111111 and 378282246310005", "expect_match": True, "id": "compound-two-cc"},
    {"text": "Backup SSN 678-90-1234 for recovery", "expect_match": True, "id": "ssn-backup"},
    {"text": "Invoice total $1,234.56 no PII here", "expect_match": False, "id": "clean-invoice"},
    {"text": "Conference call at 123-456-7890 ext 100", "expect_match": False, "id": "clean-phone-ext"},
    {"text": "CC on file: 5500000000000004 exp 12/28", "expect_match": True, "id": "cc-with-expiry"},
    {"text": "Fax number: 987-654-3210", "expect_match": False, "id": "clean-fax"},
]

assert len(TEST_INPUTS) == 100, f"Expected 100 inputs, got {len(TEST_INPUTS)}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDetectionParity:
    """Run 100 inputs through the detection API and verify results."""

    @pytest.mark.parametrize(
        "test_input",
        TEST_INPUTS,
        ids=[t["id"] for t in TEST_INPUTS],
    )
    def test_detection_result(self, client: httpx.Client, test_input: dict):
        """Each input should match or not match as expected."""
        text = test_input["text"]
        expect_match = test_input["expect_match"]

        if not text:
            # Skip empty text — API may reject it
            pytest.skip("Empty text input")

        resp = client.post("/api/detect", json={"text": text})
        assert resp.status_code == 200, f"[{test_input['id']}] API error: {resp.text}"
        data = resp.json()

        matches = data.get("matches", [])
        total = data.get("total_matches", len(matches))

        if expect_match:
            assert total > 0, (
                f"[{test_input['id']}] Expected match but got 0. "
                f"Text: {text[:80]}..."
            )
        else:
            assert total == 0, (
                f"[{test_input['id']}] Expected no match but got {total}. "
                f"Text: {text[:80]}... Matches: {matches}"
            )

    def test_total_input_count(self):
        """Confirm we have exactly 100 test inputs."""
        assert len(TEST_INPUTS) == 100
