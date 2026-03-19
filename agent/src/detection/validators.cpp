/*
 * validators.cpp
 * AkesoDLP Agent - Data Identifier Validators
 *
 * Checksum and format validators to reduce false positives from
 * regex/keyword matches. Each validator takes a raw match string
 * and returns Valid, Invalid, or Inconclusive.
 */

#include "akeso/detection/validators.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <string>

namespace akeso::dlp {

/* ================================================================== */
/*  Helpers                                                             */
/* ================================================================== */

namespace {

/* Strip non-digit characters (spaces, dashes, etc.) */
std::string ExtractDigits(std::string_view input) {
    std::string digits;
    digits.reserve(input.size());
    for (char c : input) {
        if (c >= '0' && c <= '9') digits += c;
    }
    return digits;
}

/* Strip non-alphanumeric characters */
std::string ExtractAlnum(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    for (char c : input) {
        if (std::isalnum(static_cast<unsigned char>(c))) result += c;
    }
    return result;
}

/* Parse a substring as an integer, returns -1 on failure */
int ParseInt(std::string_view s) {
    int val = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val);
    if (ec != std::errc{}) return -1;
    return val;
}

bool IsAlpha(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) != 0;
}

bool IsDigit(char c) {
    return c >= '0' && c <= '9';
}

bool IsLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

int DaysInMonth(int month, int year) {
    static constexpr int days[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12) return 0;
    if (month == 2 && IsLeapYear(year)) return 29;
    return days[month];
}

}  // anonymous namespace

/* ================================================================== */
/*  1. Credit Card — Luhn algorithm                                    */
/* ================================================================== */

namespace validators {

ValidationResult ValidateCreditCard(std::string_view input) {
    std::string digits = ExtractDigits(input);

    /* Credit card numbers are 13-19 digits */
    if (digits.size() < 13 || digits.size() > 19) {
        return ValidationResult::Invalid;
    }

    /* Luhn algorithm */
    int sum = 0;
    bool double_digit = false;

    for (int i = static_cast<int>(digits.size()) - 1; i >= 0; --i) {
        int d = digits[i] - '0';
        if (double_digit) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        double_digit = !double_digit;
    }

    return (sum % 10 == 0) ? ValidationResult::Valid : ValidationResult::Invalid;
}

/* ================================================================== */
/*  2. SSN — Area/group number validation                              */
/* ================================================================== */

ValidationResult ValidateSSN(std::string_view input) {
    std::string digits = ExtractDigits(input);

    if (digits.size() != 9) {
        return ValidationResult::Invalid;
    }

    /* Area number (first 3 digits) */
    int area = ParseInt(std::string_view(digits.data(), 3));
    if (area < 0) return ValidationResult::Invalid;

    /* Invalid area numbers: 000, 666, 900-999 */
    if (area == 0 || area == 666 || area >= 900) {
        return ValidationResult::Invalid;
    }

    /* Group number (middle 2 digits) must not be 00 */
    int group = ParseInt(std::string_view(digits.data() + 3, 2));
    if (group == 0) return ValidationResult::Invalid;

    /* Serial number (last 4 digits) must not be 0000 */
    int serial = ParseInt(std::string_view(digits.data() + 5, 4));
    if (serial == 0) return ValidationResult::Invalid;

    return ValidationResult::Valid;
}

/* ================================================================== */
/*  3. IBAN — MOD-97 checksum (ISO 13616)                              */
/* ================================================================== */

ValidationResult ValidateIBAN(std::string_view input) {
    std::string alnum = ExtractAlnum(input);

    if (alnum.size() < 5 || alnum.size() > 34) {
        return ValidationResult::Invalid;
    }

    /* First two chars must be letters (country code) */
    if (!IsAlpha(alnum[0]) || !IsAlpha(alnum[1])) {
        return ValidationResult::Invalid;
    }

    /* Next two chars must be digits (check digits) */
    if (!IsDigit(alnum[2]) || !IsDigit(alnum[3])) {
        return ValidationResult::Invalid;
    }

    /* Rearrange: move first 4 characters to the end */
    std::string rearranged = alnum.substr(4) + alnum.substr(0, 4);

    /* Convert letters to numbers: A=10, B=11, ..., Z=35 */
    std::string numeric;
    numeric.reserve(rearranged.size() * 2);
    for (char c : rearranged) {
        if (IsDigit(c)) {
            numeric += c;
        } else {
            int val = std::toupper(static_cast<unsigned char>(c)) - 'A' + 10;
            numeric += std::to_string(val);
        }
    }

    /* Compute MOD-97 using piece-wise arithmetic to avoid big integers */
    int remainder = 0;
    for (char c : numeric) {
        remainder = (remainder * 10 + (c - '0')) % 97;
    }

    return (remainder == 1) ? ValidationResult::Valid : ValidationResult::Invalid;
}

/* ================================================================== */
/*  4. ABA Routing Number — 3-7-1 weighted checksum                    */
/* ================================================================== */

ValidationResult ValidateABA(std::string_view input) {
    std::string digits = ExtractDigits(input);

    if (digits.size() != 9) {
        return ValidationResult::Invalid;
    }

    /* 3-7-1 weighted checksum */
    const int weights[] = {3, 7, 1, 3, 7, 1, 3, 7, 1};
    int sum = 0;
    for (int i = 0; i < 9; ++i) {
        sum += (digits[i] - '0') * weights[i];
    }

    return (sum % 10 == 0) ? ValidationResult::Valid : ValidationResult::Invalid;
}

/* ================================================================== */
/*  5. US Phone — Format validation                                    */
/* ================================================================== */

ValidationResult ValidateUSPhone(std::string_view input) {
    std::string digits = ExtractDigits(input);

    /* Accept 10 or 11 digits (with leading 1) */
    if (digits.size() == 11 && digits[0] == '1') {
        digits = digits.substr(1);
    }

    if (digits.size() != 10) {
        return ValidationResult::Invalid;
    }

    /* Area code cannot start with 0 or 1 */
    if (digits[0] == '0' || digits[0] == '1') {
        return ValidationResult::Invalid;
    }

    /* Exchange code (digits 3-5) cannot start with 0 or 1
     * Note: relaxed — modern NANP allows exchange codes starting with 1 */
    if (digits[3] == '0') {
        return ValidationResult::Invalid;
    }

    return ValidationResult::Valid;
}

/* ================================================================== */
/*  6. Email — Simplified RFC 5321 format                              */
/* ================================================================== */

ValidationResult ValidateEmail(std::string_view input) {
    /* Trim whitespace */
    size_t start = 0;
    size_t end = input.size();
    while (start < end && std::isspace(static_cast<unsigned char>(input[start]))) ++start;
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) --end;
    std::string_view trimmed = input.substr(start, end - start);

    if (trimmed.empty()) return ValidationResult::Invalid;

    /* Find @ */
    auto at_pos = trimmed.find('@');
    if (at_pos == std::string_view::npos || at_pos == 0 || at_pos == trimmed.size() - 1) {
        return ValidationResult::Invalid;
    }

    /* Only one @ allowed */
    if (trimmed.find('@', at_pos + 1) != std::string_view::npos) {
        return ValidationResult::Invalid;
    }

    auto local = trimmed.substr(0, at_pos);
    auto domain = trimmed.substr(at_pos + 1);

    /* Local part: max 64 chars */
    if (local.size() > 64) return ValidationResult::Invalid;

    /* Domain must contain at least one dot */
    if (domain.find('.') == std::string_view::npos) {
        return ValidationResult::Invalid;
    }

    /* Domain cannot start or end with dot or hyphen */
    if (domain.front() == '.' || domain.front() == '-' ||
        domain.back() == '.' || domain.back() == '-') {
        return ValidationResult::Invalid;
    }

    /* TLD must be at least 2 characters */
    auto last_dot = domain.rfind('.');
    if (last_dot == std::string_view::npos || domain.size() - last_dot - 1 < 2) {
        return ValidationResult::Invalid;
    }

    return ValidationResult::Valid;
}

/* ================================================================== */
/*  7. US Passport — 1 letter + 8 digits                               */
/* ================================================================== */

ValidationResult ValidateUSPassport(std::string_view input) {
    /* Trim whitespace */
    size_t start = 0;
    size_t end = input.size();
    while (start < end && std::isspace(static_cast<unsigned char>(input[start]))) ++start;
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) --end;
    std::string_view trimmed = input.substr(start, end - start);

    if (trimmed.size() != 9) return ValidationResult::Invalid;

    /* First character must be a letter */
    if (!IsAlpha(trimmed[0])) return ValidationResult::Invalid;

    /* Remaining 8 must be digits */
    for (size_t i = 1; i < 9; ++i) {
        if (!IsDigit(trimmed[i])) return ValidationResult::Invalid;
    }

    return ValidationResult::Valid;
}

/* ================================================================== */
/*  8. US Driver License — Basic format validation                     */
/* ================================================================== */

ValidationResult ValidateUSDriverLicense(std::string_view input) {
    /* Trim whitespace */
    size_t start = 0;
    size_t end = input.size();
    while (start < end && std::isspace(static_cast<unsigned char>(input[start]))) ++start;
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) --end;
    std::string_view trimmed = input.substr(start, end - start);

    /* Most US DLs: 1 letter + 7-12 digits, or all digits (7-13) */
    if (trimmed.size() < 7 || trimmed.size() > 13) {
        return ValidationResult::Invalid;
    }

    /* Check if first char is letter followed by digits */
    if (IsAlpha(trimmed[0])) {
        for (size_t i = 1; i < trimmed.size(); ++i) {
            if (!IsDigit(trimmed[i])) return ValidationResult::Invalid;
        }
        return ValidationResult::Valid;
    }

    /* All digits format */
    for (char c : trimmed) {
        if (!IsDigit(c)) return ValidationResult::Invalid;
    }

    return ValidationResult::Valid;
}

/* ================================================================== */
/*  9. IPv4 — Octet range 0-255                                        */
/* ================================================================== */

ValidationResult ValidateIPv4(std::string_view input) {
    /* Trim whitespace */
    size_t start = 0;
    size_t end = input.size();
    while (start < end && std::isspace(static_cast<unsigned char>(input[start]))) ++start;
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) --end;
    std::string_view trimmed = input.substr(start, end - start);

    int octets = 0;
    size_t pos = 0;

    while (pos <= trimmed.size() && octets < 4) {
        /* Find next dot or end */
        size_t dot = trimmed.find('.', pos);
        if (dot == std::string_view::npos) dot = trimmed.size();

        auto part = trimmed.substr(pos, dot - pos);
        if (part.empty() || part.size() > 3) return ValidationResult::Invalid;

        /* No leading zeros (except "0" itself) */
        if (part.size() > 1 && part[0] == '0') return ValidationResult::Invalid;

        int val = ParseInt(part);
        if (val < 0 || val > 255) return ValidationResult::Invalid;

        ++octets;
        pos = dot + 1;
    }

    if (octets != 4) return ValidationResult::Invalid;

    /* Reject 0.0.0.0 and 255.255.255.255 as likely not PII */
    if (trimmed == "0.0.0.0" || trimmed == "255.255.255.255") {
        return ValidationResult::Invalid;
    }

    return ValidationResult::Valid;
}

/* ================================================================== */
/*  10. Date of Birth — Calendar validity (MM/DD/YYYY)                 */
/* ================================================================== */

ValidationResult ValidateDateOfBirth(std::string_view input) {
    /* Trim whitespace */
    size_t start = 0;
    size_t end = input.size();
    while (start < end && std::isspace(static_cast<unsigned char>(input[start]))) ++start;
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) --end;
    std::string_view trimmed = input.substr(start, end - start);

    /* Expected format: MM/DD/YYYY (10 chars) */
    if (trimmed.size() != 10) return ValidationResult::Invalid;
    if (trimmed[2] != '/' || trimmed[5] != '/') return ValidationResult::Invalid;

    int month = ParseInt(trimmed.substr(0, 2));
    int day = ParseInt(trimmed.substr(3, 2));
    int year = ParseInt(trimmed.substr(6, 4));

    if (month < 1 || month > 12) return ValidationResult::Invalid;
    if (year < 1900 || year > 2025) return ValidationResult::Invalid;
    if (day < 1 || day > DaysInMonth(month, year)) return ValidationResult::Invalid;

    return ValidationResult::Valid;
}

}  // namespace validators

/* ================================================================== */
/*  Convenience dispatcher                                              */
/* ================================================================== */

ValidationResult ValidateDataIdentifier(std::string_view type_name,
                                         std::string_view input) {
    if (type_name == "US SSN"       || type_name == "SSN")
        return validators::ValidateSSN(input);
    if (type_name == "Visa CC"      || type_name == "MasterCard CC" ||
        type_name == "Credit Card"  || type_name == "CC")
        return validators::ValidateCreditCard(input);
    if (type_name == "IBAN")
        return validators::ValidateIBAN(input);
    if (type_name == "ABA"          || type_name == "ABA Routing")
        return validators::ValidateABA(input);
    if (type_name == "US Phone"     || type_name == "Phone")
        return validators::ValidateUSPhone(input);
    if (type_name == "Email")
        return validators::ValidateEmail(input);
    if (type_name == "US Passport"  || type_name == "Passport")
        return validators::ValidateUSPassport(input);
    if (type_name == "US DL"        || type_name == "Driver License")
        return validators::ValidateUSDriverLicense(input);
    if (type_name == "IPv4")
        return validators::ValidateIPv4(input);
    if (type_name == "DOB"          || type_name == "Date of Birth")
        return validators::ValidateDateOfBirth(input);

    return ValidationResult::Inconclusive;
}

}  // namespace akeso::dlp
