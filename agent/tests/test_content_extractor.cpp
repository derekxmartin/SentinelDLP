/*
 * test_content_extractor.cpp
 * AkesoDLP Agent - Content Extractor Tests
 *
 * Tests: encoding detection (UTF-8, UTF-16 LE/BE, UTF-32, Latin-1),
 *        ZIP extraction with zlib inflate, nested ZIP, binary strings,
 *        Office XML extraction, dispatch by file type.
 */

#include "akeso/detection/content_extractor.h"
#include "akeso/detection/file_type_detector.h"

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include <zlib.h>

using namespace akeso::dlp;

/* ================================================================== */
/*  Helpers                                                             */
/* ================================================================== */

/* Create a minimal ZIP archive with one stored (uncompressed) entry */
static std::vector<uint8_t> MakeZipStored(const std::string& filename,
                                            const std::string& content) {
    std::vector<uint8_t> zip;

    /* Local file header */
    uint8_t lfh[] = {
        0x50, 0x4B, 0x03, 0x04,  /* Signature */
        0x14, 0x00,              /* Version needed */
        0x00, 0x00,              /* Flags */
        0x00, 0x00,              /* Compression: stored */
        0x00, 0x00,              /* Mod time */
        0x00, 0x00,              /* Mod date */
        0x00, 0x00, 0x00, 0x00,  /* CRC-32 (dummy) */
        0x00, 0x00, 0x00, 0x00,  /* Compressed size */
        0x00, 0x00, 0x00, 0x00,  /* Uncompressed size */
        0x00, 0x00,              /* Filename length */
        0x00, 0x00,              /* Extra field length */
    };

    uint32_t size = static_cast<uint32_t>(content.size());
    uint16_t name_len = static_cast<uint16_t>(filename.size());

    /* Compute CRC-32 */
    uint32_t crc = static_cast<uint32_t>(
        crc32(0L, reinterpret_cast<const Bytef*>(content.data()),
              static_cast<uInt>(content.size())));

    /* Fill in sizes */
    std::memcpy(lfh + 14, &crc, 4);
    std::memcpy(lfh + 18, &size, 4);
    std::memcpy(lfh + 22, &size, 4);
    std::memcpy(lfh + 26, &name_len, 2);

    zip.insert(zip.end(), lfh, lfh + 30);
    zip.insert(zip.end(), filename.begin(), filename.end());
    zip.insert(zip.end(), content.begin(), content.end());

    return zip;
}

/* Create a ZIP archive with one deflate-compressed entry */
static std::vector<uint8_t> MakeZipDeflated(const std::string& filename,
                                              const std::string& content) {
    /* Compress with raw deflate */
    std::vector<uint8_t> compressed(content.size() + 256);
    z_stream strm{};
    deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(content.data()));
    strm.avail_in = static_cast<uInt>(content.size());
    strm.next_out = compressed.data();
    strm.avail_out = static_cast<uInt>(compressed.size());
    deflate(&strm, Z_FINISH);
    size_t comp_size = strm.total_out;
    deflateEnd(&strm);
    compressed.resize(comp_size);

    std::vector<uint8_t> zip;

    uint8_t lfh[] = {
        0x50, 0x4B, 0x03, 0x04,
        0x14, 0x00,
        0x00, 0x00,
        0x08, 0x00,              /* Compression: deflate */
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  /* CRC-32 */
        0x00, 0x00, 0x00, 0x00,  /* Compressed size */
        0x00, 0x00, 0x00, 0x00,  /* Uncompressed size */
        0x00, 0x00,              /* Filename length */
        0x00, 0x00,              /* Extra field length */
    };

    uint32_t crc = static_cast<uint32_t>(
        crc32(0L, reinterpret_cast<const Bytef*>(content.data()),
              static_cast<uInt>(content.size())));
    uint32_t c_size = static_cast<uint32_t>(comp_size);
    uint32_t u_size = static_cast<uint32_t>(content.size());
    uint16_t name_len = static_cast<uint16_t>(filename.size());

    std::memcpy(lfh + 14, &crc, 4);
    std::memcpy(lfh + 18, &c_size, 4);
    std::memcpy(lfh + 22, &u_size, 4);
    std::memcpy(lfh + 26, &name_len, 2);

    zip.insert(zip.end(), lfh, lfh + 30);
    zip.insert(zip.end(), filename.begin(), filename.end());
    zip.insert(zip.end(), compressed.begin(), compressed.end());

    return zip;
}

/* ================================================================== */
/*  Plain text — encoding detection                                     */
/* ================================================================== */

class ContentExtractorTest : public ::testing::Test {
protected:
    ContentExtractor extractor_;
};

TEST_F(ContentExtractorTest, PlainText_UTF8) {
    std::string text = "Hello, World! This is UTF-8 text.";
    auto result = extractor_.ExtractPlainText(
        reinterpret_cast<const uint8_t*>(text.data()), text.size());
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.text, text);
}

TEST_F(ContentExtractorTest, PlainText_UTF8_BOM) {
    std::vector<uint8_t> data = {0xEF, 0xBB, 0xBF};  /* BOM */
    std::string text = "BOM text";
    data.insert(data.end(), text.begin(), text.end());

    auto result = extractor_.ExtractPlainText(data.data(), data.size());
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.text, "BOM text");
}

TEST_F(ContentExtractorTest, PlainText_UTF16_LE) {
    /* UTF-16 LE BOM + "Hi" */
    std::vector<uint8_t> data = {
        0xFF, 0xFE,  /* BOM */
        'H', 0x00,
        'i', 0x00,
    };
    auto result = extractor_.ExtractPlainText(data.data(), data.size());
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.text, "Hi");
}

TEST_F(ContentExtractorTest, PlainText_UTF16_BE) {
    /* UTF-16 BE BOM + "Hi" */
    std::vector<uint8_t> data = {
        0xFE, 0xFF,  /* BOM */
        0x00, 'H',
        0x00, 'i',
    };
    auto result = extractor_.ExtractPlainText(data.data(), data.size());
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.text, "Hi");
}

TEST_F(ContentExtractorTest, PlainText_UTF16_LE_NoBOM) {
    /* UTF-16 LE without BOM — heuristic detection */
    std::vector<uint8_t> data;
    std::string text = "Hello World test data for encoding";
    for (char c : text) {
        data.push_back(static_cast<uint8_t>(c));
        data.push_back(0x00);
    }
    auto result = extractor_.ExtractPlainText(data.data(), data.size());
    EXPECT_TRUE(result.success);
    EXPECT_NE(result.text.find("Hello"), std::string::npos);
}

TEST_F(ContentExtractorTest, PlainText_Latin1) {
    /* Latin-1: bytes 0x80-0xFF that are NOT valid UTF-8 */
    std::vector<uint8_t> data = {
        'H', 'e', 'l', 'l', 'o', ' ',
        0xC0,  /* Invalid UTF-8 lead byte followed by non-continuation */
        0x20,  /* space — not a valid continuation */
        0xE9,  /* é in Latin-1, but isolated (invalid UTF-8) */
        0x20,
    };
    auto result = extractor_.ExtractPlainText(data.data(), data.size());
    EXPECT_TRUE(result.success);
    /* Should be converted from Latin-1 to UTF-8 */
    EXPECT_FALSE(result.text.empty());
}

TEST_F(ContentExtractorTest, PlainText_Empty) {
    auto result = extractor_.ExtractPlainText(nullptr, 0);
    EXPECT_FALSE(result.success);
}

/* ================================================================== */
/*  ZIP extraction                                                      */
/* ================================================================== */

TEST_F(ContentExtractorTest, ZIP_StoredEntry) {
    std::string content = "This is stored content with SSN 123-45-6789";
    auto zip = MakeZipStored("test.txt", content);

    auto results = extractor_.ExtractZip(zip.data(), zip.size(), "archive.zip");
    ASSERT_GE(results.size(), 1u);

    bool found = false;
    for (auto& r : results) {
        if (r.success && r.text.find("123-45-6789") != std::string::npos) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(ContentExtractorTest, ZIP_DeflatedEntry) {
    std::string content = "Compressed content with credit card 4111111111111111 here";
    auto zip = MakeZipDeflated("data.txt", content);

    auto results = extractor_.ExtractZip(zip.data(), zip.size(), "archive.zip");
    ASSERT_GE(results.size(), 1u);

    bool found = false;
    for (auto& r : results) {
        if (r.success && r.text.find("4111111111111111") != std::string::npos) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(ContentExtractorTest, ZIP_MultipleEntries) {
    /* Concatenate two stored entries */
    auto zip1 = MakeZipStored("file1.txt", "First file content");
    auto zip2 = MakeZipStored("file2.txt", "Second file content");

    std::vector<uint8_t> combined;
    combined.insert(combined.end(), zip1.begin(), zip1.end());
    combined.insert(combined.end(), zip2.begin(), zip2.end());

    auto results = extractor_.ExtractZip(combined.data(), combined.size());
    EXPECT_GE(results.size(), 2u);
}

TEST_F(ContentExtractorTest, ZIP_NestedZip) {
    /* Inner ZIP */
    auto inner = MakeZipStored("inner.txt", "Nested secret data");
    std::string inner_str(inner.begin(), inner.end());

    /* Outer ZIP containing the inner ZIP */
    auto outer = MakeZipStored("inner.zip", inner_str);

    ExtractionOptions opts;
    opts.max_zip_depth = 2;
    ContentExtractor extractor(opts);

    auto results = extractor.ExtractZip(outer.data(), outer.size(), "outer.zip");

    /* Should find the nested content */
    bool found = false;
    for (auto& r : results) {
        if (r.success && r.text.find("Nested secret data") != std::string::npos) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(ContentExtractorTest, ZIP_MaxDepthEnforced) {
    /* Create 3-level nested ZIP but set max_depth = 1 */
    auto inner = MakeZipStored("deep.txt", "Too deep content");
    std::string inner_str(inner.begin(), inner.end());
    auto mid = MakeZipStored("mid.zip", inner_str);
    std::string mid_str(mid.begin(), mid.end());
    auto outer = MakeZipStored("outer.zip", mid_str);

    ExtractionOptions opts;
    opts.max_zip_depth = 1;
    ContentExtractor extractor(opts);

    auto results = extractor.ExtractZip(outer.data(), outer.size(), "outer.zip");

    /* Should NOT find the deeply nested content */
    bool found_deep = false;
    for (auto& r : results) {
        if (r.text.find("Too deep content") != std::string::npos) {
            found_deep = true;
        }
    }
    EXPECT_FALSE(found_deep);
}

TEST_F(ContentExtractorTest, ZIP_Empty) {
    auto results = extractor_.ExtractZip(nullptr, 0);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_FALSE(results[0].success);
}

/* ================================================================== */
/*  Binary string extraction                                            */
/* ================================================================== */

TEST_F(ContentExtractorTest, BinaryStrings_ExtractsPrintable) {
    std::vector<uint8_t> data;
    /* Binary noise */
    for (int i = 0; i < 20; ++i) data.push_back(static_cast<uint8_t>(i));
    /* Printable string */
    std::string secret = "password=hunter2";
    data.insert(data.end(), secret.begin(), secret.end());
    /* More binary noise */
    for (int i = 0; i < 20; ++i) data.push_back(static_cast<uint8_t>(i));

    auto result = extractor_.ExtractBinaryStrings(data.data(), data.size());
    EXPECT_TRUE(result.success);
    EXPECT_NE(result.text.find("password=hunter2"), std::string::npos);
}

TEST_F(ContentExtractorTest, BinaryStrings_ShortRunsIgnored) {
    std::vector<uint8_t> data;
    for (int i = 0; i < 10; ++i) data.push_back(0x00);
    data.push_back('a');
    data.push_back('b');
    data.push_back('c');  /* Only 3 chars — below default min_string_run of 6 */
    for (int i = 0; i < 10; ++i) data.push_back(0x00);

    auto result = extractor_.ExtractBinaryStrings(data.data(), data.size());
    EXPECT_FALSE(result.success);  /* No strings long enough */
}

TEST_F(ContentExtractorTest, BinaryStrings_Empty) {
    auto result = extractor_.ExtractBinaryStrings(nullptr, 0);
    EXPECT_FALSE(result.success);
}

/* ================================================================== */
/*  Main dispatch                                                       */
/* ================================================================== */

TEST_F(ContentExtractorTest, Dispatch_PlainText) {
    std::string text = "Plain text with email user@example.com";
    FileTypeResult ft{"Text", "text/plain", ".txt", FileCategory::Document, 50};

    auto results = extractor_.Extract(
        reinterpret_cast<const uint8_t*>(text.data()), text.size(), ft, "doc.txt");
    ASSERT_GE(results.size(), 1u);
    EXPECT_TRUE(results[0].success);
    EXPECT_NE(results[0].text.find("user@example.com"), std::string::npos);
}

TEST_F(ContentExtractorTest, Dispatch_Script) {
    std::string script = "#!/usr/bin/env python3\nprint('secret')";
    FileTypeResult ft{"Python", "text/x-python", ".py", FileCategory::Script, 50};

    auto results = extractor_.Extract(
        reinterpret_cast<const uint8_t*>(script.data()), script.size(), ft, "script.py");
    ASSERT_GE(results.size(), 1u);
    EXPECT_TRUE(results[0].success);
    EXPECT_NE(results[0].text.find("secret"), std::string::npos);
}

TEST_F(ContentExtractorTest, Dispatch_ZIPArchive) {
    auto zip = MakeZipStored("data.txt", "sensitive data inside zip");
    FileTypeResult ft{"ZIP", "application/zip", ".zip", FileCategory::Archive, 90};

    auto results = extractor_.Extract(zip.data(), zip.size(), ft, "archive.zip");
    ASSERT_GE(results.size(), 1u);

    bool found = false;
    for (auto& r : results) {
        if (r.success && r.text.find("sensitive data") != std::string::npos) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(ContentExtractorTest, Dispatch_Binary) {
    /* PE header followed by a string */
    std::vector<uint8_t> data = {0x4D, 0x5A, 0x90, 0x00};
    data.resize(64, 0);
    std::string str = "embedded_secret_key_value";
    data.insert(data.end(), str.begin(), str.end());
    data.resize(data.size() + 32, 0);

    FileTypeResult ft{"PE Executable", "application/x-dosexec", ".exe",
                       FileCategory::Executable, 90};

    auto results = extractor_.Extract(data.data(), data.size(), ft, "app.exe");
    ASSERT_GE(results.size(), 1u);
    EXPECT_NE(results[0].text.find("embedded_secret_key_value"), std::string::npos);
}

TEST_F(ContentExtractorTest, Dispatch_NullInput) {
    FileTypeResult ft{"Unknown", "", "", FileCategory::Unknown, 0};
    auto results = extractor_.Extract(static_cast<const uint8_t*>(nullptr), 0, ft);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_FALSE(results[0].success);
}
