/*
 * test_validators.cpp
 * AkesoDLP Agent - Data Identifier Validator Tests
 *
 * Tests: Luhn (CC), SSN area validation, IBAN MOD-97, ABA checksum,
 *        US Phone, Email, US Passport, US DL, IPv4, DOB.
 */

#include "akeso/detection/validators.h"

#include <gtest/gtest.h>

#include <string>

using namespace akeso::dlp;
using VR = ValidationResult;

/* ================================================================== */
/*  1. Credit Card — Luhn                                              */
/* ================================================================== */

TEST(ValidatorsTest, CC_ValidVisa) {
    EXPECT_EQ(validators::ValidateCreditCard("4111111111111111"), VR::Valid);
}

TEST(ValidatorsTest, CC_ValidVisaWithDashes) {
    EXPECT_EQ(validators::ValidateCreditCard("4111-1111-1111-1111"), VR::Valid);
}

TEST(ValidatorsTest, CC_ValidVisaWithSpaces) {
    EXPECT_EQ(validators::ValidateCreditCard("4111 1111 1111 1111"), VR::Valid);
}

TEST(ValidatorsTest, CC_ValidMasterCard) {
    EXPECT_EQ(validators::ValidateCreditCard("5500000000000004"), VR::Valid);
}

TEST(ValidatorsTest, CC_ValidAmex) {
    EXPECT_EQ(validators::ValidateCreditCard("378282246310005"), VR::Valid);
}

TEST(ValidatorsTest, CC_InvalidLuhn) {
    EXPECT_EQ(validators::ValidateCreditCard("4111111111111112"), VR::Invalid);
}

TEST(ValidatorsTest, CC_TooShort) {
    EXPECT_EQ(validators::ValidateCreditCard("411111"), VR::Invalid);
}

TEST(ValidatorsTest, CC_TooLong) {
    EXPECT_EQ(validators::ValidateCreditCard("41111111111111111111"), VR::Invalid);
}

/* ================================================================== */
/*  2. SSN                                                              */
/* ================================================================== */

TEST(ValidatorsTest, SSN_Valid) {
    EXPECT_EQ(validators::ValidateSSN("123-45-6789"), VR::Valid);
}

TEST(ValidatorsTest, SSN_ValidNoSeparator) {
    EXPECT_EQ(validators::ValidateSSN("123456789"), VR::Valid);
}

TEST(ValidatorsTest, SSN_Area000_Rejected) {
    EXPECT_EQ(validators::ValidateSSN("000-45-6789"), VR::Invalid);
}

TEST(ValidatorsTest, SSN_Area666_Rejected) {
    EXPECT_EQ(validators::ValidateSSN("666-45-6789"), VR::Invalid);
}

TEST(ValidatorsTest, SSN_Area900Plus_Rejected) {
    EXPECT_EQ(validators::ValidateSSN("900-45-6789"), VR::Invalid);
    EXPECT_EQ(validators::ValidateSSN("999-45-6789"), VR::Invalid);
}

TEST(ValidatorsTest, SSN_Group00_Rejected) {
    EXPECT_EQ(validators::ValidateSSN("123-00-6789"), VR::Invalid);
}

TEST(ValidatorsTest, SSN_Serial0000_Rejected) {
    EXPECT_EQ(validators::ValidateSSN("123-45-0000"), VR::Invalid);
}

TEST(ValidatorsTest, SSN_WrongLength) {
    EXPECT_EQ(validators::ValidateSSN("1234-56-7890"), VR::Invalid);  /* 10 digits after strip */
    EXPECT_EQ(validators::ValidateSSN("12345678"), VR::Invalid);      /* 8 digits */
}

/* ================================================================== */
/*  3. IBAN — MOD-97                                                    */
/* ================================================================== */

TEST(ValidatorsTest, IBAN_ValidDE) {
    EXPECT_EQ(validators::ValidateIBAN("DE89370400440532013000"), VR::Valid);
}

TEST(ValidatorsTest, IBAN_ValidGB) {
    EXPECT_EQ(validators::ValidateIBAN("GB29NWBK60161331926819"), VR::Valid);
}

TEST(ValidatorsTest, IBAN_ValidWithSpaces) {
    EXPECT_EQ(validators::ValidateIBAN("DE89 3704 0044 0532 0130 00"), VR::Valid);
}

TEST(ValidatorsTest, IBAN_InvalidChecksum) {
    EXPECT_EQ(validators::ValidateIBAN("DE00370400440532013000"), VR::Invalid);
}

TEST(ValidatorsTest, IBAN_TooShort) {
    EXPECT_EQ(validators::ValidateIBAN("DE89"), VR::Invalid);
}

TEST(ValidatorsTest, IBAN_NoCountryCode) {
    EXPECT_EQ(validators::ValidateIBAN("12370400440532013000"), VR::Invalid);
}

/* ================================================================== */
/*  4. ABA Routing — 3-7-1 checksum                                    */
/* ================================================================== */

TEST(ValidatorsTest, ABA_Valid) {
    /* Bank of America: 026009593 */
    EXPECT_EQ(validators::ValidateABA("026009593"), VR::Valid);
}

TEST(ValidatorsTest, ABA_ValidChase) {
    /* JPMorgan Chase: 021000021 */
    EXPECT_EQ(validators::ValidateABA("021000021"), VR::Valid);
}

TEST(ValidatorsTest, ABA_Invalid) {
    EXPECT_EQ(validators::ValidateABA("123456789"), VR::Invalid);
}

TEST(ValidatorsTest, ABA_WrongLength) {
    EXPECT_EQ(validators::ValidateABA("12345"), VR::Invalid);
}

/* ================================================================== */
/*  5. US Phone                                                         */
/* ================================================================== */

TEST(ValidatorsTest, Phone_ValidFormatted) {
    EXPECT_EQ(validators::ValidateUSPhone("(555) 123-4567"), VR::Valid);
}

TEST(ValidatorsTest, Phone_ValidPlain) {
    EXPECT_EQ(validators::ValidateUSPhone("5551234567"), VR::Valid);
}

TEST(ValidatorsTest, Phone_ValidWithCountryCode) {
    EXPECT_EQ(validators::ValidateUSPhone("1-555-123-4567"), VR::Valid);
}

TEST(ValidatorsTest, Phone_AreaStartsWith0) {
    EXPECT_EQ(validators::ValidateUSPhone("(055) 123-4567"), VR::Invalid);
}

TEST(ValidatorsTest, Phone_AreaStartsWith1) {
    EXPECT_EQ(validators::ValidateUSPhone("(155) 123-4567"), VR::Invalid);
}

TEST(ValidatorsTest, Phone_ExchangeStartsWith0) {
    EXPECT_EQ(validators::ValidateUSPhone("(555) 023-4567"), VR::Invalid);
}

TEST(ValidatorsTest, Phone_ExchangeStartsWith1_Valid) {
    /* Modern NANP allows exchange codes starting with 1 */
    EXPECT_EQ(validators::ValidateUSPhone("(555) 123-4567"), VR::Valid);
}

/* ================================================================== */
/*  6. Email                                                            */
/* ================================================================== */

TEST(ValidatorsTest, Email_Valid) {
    EXPECT_EQ(validators::ValidateEmail("user@example.com"), VR::Valid);
}

TEST(ValidatorsTest, Email_ValidComplex) {
    EXPECT_EQ(validators::ValidateEmail("user.name+tag@sub.domain.com"), VR::Valid);
}

TEST(ValidatorsTest, Email_NoAt) {
    EXPECT_EQ(validators::ValidateEmail("userexample.com"), VR::Invalid);
}

TEST(ValidatorsTest, Email_MultipleAt) {
    EXPECT_EQ(validators::ValidateEmail("user@@example.com"), VR::Invalid);
}

TEST(ValidatorsTest, Email_NoDomain) {
    EXPECT_EQ(validators::ValidateEmail("user@"), VR::Invalid);
}

TEST(ValidatorsTest, Email_NoDot) {
    EXPECT_EQ(validators::ValidateEmail("user@examplecom"), VR::Invalid);
}

TEST(ValidatorsTest, Email_ShortTLD) {
    EXPECT_EQ(validators::ValidateEmail("user@example.c"), VR::Invalid);
}

/* ================================================================== */
/*  7. US Passport                                                      */
/* ================================================================== */

TEST(ValidatorsTest, Passport_Valid) {
    EXPECT_EQ(validators::ValidateUSPassport("C12345678"), VR::Valid);
}

TEST(ValidatorsTest, Passport_ValidLowerCase) {
    /* Validator just checks format — letter + 8 digits */
    EXPECT_EQ(validators::ValidateUSPassport("c12345678"), VR::Valid);
}

TEST(ValidatorsTest, Passport_NoLetter) {
    EXPECT_EQ(validators::ValidateUSPassport("123456789"), VR::Invalid);
}

TEST(ValidatorsTest, Passport_TooShort) {
    EXPECT_EQ(validators::ValidateUSPassport("C1234567"), VR::Invalid);
}

TEST(ValidatorsTest, Passport_TooLong) {
    EXPECT_EQ(validators::ValidateUSPassport("C123456789"), VR::Invalid);
}

/* ================================================================== */
/*  8. US Driver License                                                */
/* ================================================================== */

TEST(ValidatorsTest, DL_LetterPlusDigits) {
    EXPECT_EQ(validators::ValidateUSDriverLicense("A1234567"), VR::Valid);
}

TEST(ValidatorsTest, DL_AllDigits) {
    EXPECT_EQ(validators::ValidateUSDriverLicense("12345678"), VR::Valid);
}

TEST(ValidatorsTest, DL_TooShort) {
    EXPECT_EQ(validators::ValidateUSDriverLicense("A123"), VR::Invalid);
}

TEST(ValidatorsTest, DL_TooLong) {
    EXPECT_EQ(validators::ValidateUSDriverLicense("A12345678901234"), VR::Invalid);
}

/* ================================================================== */
/*  9. IPv4                                                             */
/* ================================================================== */

TEST(ValidatorsTest, IPv4_Valid) {
    EXPECT_EQ(validators::ValidateIPv4("192.168.1.100"), VR::Valid);
}

TEST(ValidatorsTest, IPv4_ValidMin) {
    EXPECT_EQ(validators::ValidateIPv4("1.0.0.1"), VR::Valid);
}

TEST(ValidatorsTest, IPv4_ValidMax) {
    EXPECT_EQ(validators::ValidateIPv4("254.254.254.254"), VR::Valid);
}

TEST(ValidatorsTest, IPv4_OctetOver255) {
    EXPECT_EQ(validators::ValidateIPv4("192.168.1.256"), VR::Invalid);
}

TEST(ValidatorsTest, IPv4_LeadingZero) {
    EXPECT_EQ(validators::ValidateIPv4("192.168.01.1"), VR::Invalid);
}

TEST(ValidatorsTest, IPv4_AllZeros) {
    EXPECT_EQ(validators::ValidateIPv4("0.0.0.0"), VR::Invalid);
}

TEST(ValidatorsTest, IPv4_Broadcast) {
    EXPECT_EQ(validators::ValidateIPv4("255.255.255.255"), VR::Invalid);
}

TEST(ValidatorsTest, IPv4_TooFewOctets) {
    EXPECT_EQ(validators::ValidateIPv4("192.168.1"), VR::Invalid);
}

/* ================================================================== */
/*  10. Date of Birth                                                   */
/* ================================================================== */

TEST(ValidatorsTest, DOB_Valid) {
    EXPECT_EQ(validators::ValidateDateOfBirth("01/15/1990"), VR::Valid);
}

TEST(ValidatorsTest, DOB_LeapDay) {
    EXPECT_EQ(validators::ValidateDateOfBirth("02/29/2000"), VR::Valid);
}

TEST(ValidatorsTest, DOB_NotLeapDay) {
    EXPECT_EQ(validators::ValidateDateOfBirth("02/29/2001"), VR::Invalid);
}

TEST(ValidatorsTest, DOB_InvalidMonth) {
    EXPECT_EQ(validators::ValidateDateOfBirth("13/01/1990"), VR::Invalid);
}

TEST(ValidatorsTest, DOB_InvalidDay) {
    EXPECT_EQ(validators::ValidateDateOfBirth("01/32/1990"), VR::Invalid);
}

TEST(ValidatorsTest, DOB_YearTooOld) {
    EXPECT_EQ(validators::ValidateDateOfBirth("01/15/1899"), VR::Invalid);
}

TEST(ValidatorsTest, DOB_YearTooNew) {
    EXPECT_EQ(validators::ValidateDateOfBirth("01/15/2030"), VR::Invalid);
}

TEST(ValidatorsTest, DOB_WrongFormat) {
    EXPECT_EQ(validators::ValidateDateOfBirth("1990-01-15"), VR::Invalid);
}

/* ================================================================== */
/*  Convenience dispatcher                                              */
/* ================================================================== */

TEST(ValidatorsTest, Dispatcher_SSN) {
    EXPECT_EQ(ValidateDataIdentifier("US SSN", "123-45-6789"), VR::Valid);
    EXPECT_EQ(ValidateDataIdentifier("SSN", "000-45-6789"), VR::Invalid);
}

TEST(ValidatorsTest, Dispatcher_CC) {
    EXPECT_EQ(ValidateDataIdentifier("Visa CC", "4111111111111111"), VR::Valid);
    EXPECT_EQ(ValidateDataIdentifier("MasterCard CC", "5500000000000004"), VR::Valid);
    EXPECT_EQ(ValidateDataIdentifier("Credit Card", "4111111111111112"), VR::Invalid);
}

TEST(ValidatorsTest, Dispatcher_Unknown) {
    EXPECT_EQ(ValidateDataIdentifier("UnknownType", "data"), VR::Inconclusive);
}
