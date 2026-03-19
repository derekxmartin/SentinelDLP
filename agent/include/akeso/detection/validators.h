/*
 * validators.h
 * AkesoDLP Agent - Data Identifier Validators
 *
 * Checksum and format validators for data identifiers detected by
 * the regex and keyword analyzers. Reduces false positives by
 * verifying structural correctness of matched patterns.
 *
 * Validators:
 *   1. Credit Card      — Luhn algorithm
 *   2. SSN              — Area/group number validation
 *   3. IBAN             — MOD-97 checksum (ISO 13616)
 *   4. ABA Routing      — 3-7-1 weighted checksum
 *   5. US Phone         — Format validation
 *   6. Email            — RFC 5321 simplified format
 *   7. US Passport      — Format validation
 *   8. US Driver License— State-aware format validation
 *   9. IPv4             — Octet range validation
 *  10. Date of Birth    — Calendar validity
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Validation result                                                   */
/* ------------------------------------------------------------------ */

enum class ValidationResult {
    Valid,
    Invalid,
    Inconclusive,  /* Pattern matched but no checksum to verify */
};

/* ------------------------------------------------------------------ */
/*  Validator functions                                                 */
/* ------------------------------------------------------------------ */

namespace validators {

/* 1. Credit Card — Luhn algorithm */
ValidationResult ValidateCreditCard(std::string_view input);

/* 2. SSN — Area number must not be 000, 666, or 900-999 */
ValidationResult ValidateSSN(std::string_view input);

/* 3. IBAN — MOD-97 checksum (ISO 13616) */
ValidationResult ValidateIBAN(std::string_view input);

/* 4. ABA Routing Number — 3-7-1 weighted checksum */
ValidationResult ValidateABA(std::string_view input);

/* 5. US Phone — 10-digit format, area code validation */
ValidationResult ValidateUSPhone(std::string_view input);

/* 6. Email — Simplified RFC 5321 format check */
ValidationResult ValidateEmail(std::string_view input);

/* 7. US Passport — 1 letter + 8 digits */
ValidationResult ValidateUSPassport(std::string_view input);

/* 8. US Driver License — Basic format validation */
ValidationResult ValidateUSDriverLicense(std::string_view input);

/* 9. IPv4 — Octet range 0-255 */
ValidationResult ValidateIPv4(std::string_view input);

/* 10. Date of Birth — Calendar validity (MM/DD/YYYY) */
ValidationResult ValidateDateOfBirth(std::string_view input);

}  // namespace validators

/* ------------------------------------------------------------------ */
/*  Convenience: validate by identifier type name                       */
/* ------------------------------------------------------------------ */

ValidationResult ValidateDataIdentifier(std::string_view type_name,
                                         std::string_view input);

}  // namespace akeso::dlp
