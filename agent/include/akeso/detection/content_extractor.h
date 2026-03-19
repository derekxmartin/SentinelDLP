/*
 * content_extractor.h
 * AkesoDLP Agent - Content Extraction
 *
 * Extracts scannable text from files:
 *   - Plain text with encoding detection (UTF-8, UTF-16 LE/BE, UTF-32, Latin-1)
 *   - ZIP archive member extraction (max depth 2 on agent)
 *   - Binary-to-text for unknown formats (printable ASCII runs)
 *
 * Complex formats (PDF, Office XML) are forwarded to the server
 * via TTD (Time-To-Decide) rather than parsed agent-side.
 */

#pragma once

#include "akeso/detection/file_type_detector.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Extraction result                                                   */
/* ------------------------------------------------------------------ */

struct ExtractionResult {
    bool        success = false;
    std::string text;               /* Extracted UTF-8 text */
    std::string error;              /* Error message if !success */
    std::string source_name;        /* Original filename or archive member */
    FileCategory source_type = FileCategory::Unknown;
};

struct ExtractionOptions {
    size_t  max_text_size    = 52428800;  /* 50 MB cap on extracted text */
    int     max_zip_depth    = 2;         /* Max nested ZIP recursion */
    size_t  max_zip_entry    = 10485760;  /* 10 MB max per ZIP entry */
    int     max_zip_entries  = 100;       /* Max entries to extract from ZIP */
    size_t  min_string_run   = 6;         /* Min printable chars for binary extraction */
};

/* ------------------------------------------------------------------ */
/*  ContentExtractor                                                    */
/* ------------------------------------------------------------------ */

class ContentExtractor {
public:
    explicit ContentExtractor(const ExtractionOptions& opts = {});

    /*
     * Extract text from raw file content.
     * Uses file_type to decide extraction strategy.
     * Returns one or more results (ZIP archives produce multiple).
     */
    std::vector<ExtractionResult> Extract(
        const uint8_t* data, size_t length,
        const FileTypeResult& file_type,
        const std::string& filename = "") const;

    std::vector<ExtractionResult> Extract(
        const char* data, size_t length,
        const FileTypeResult& file_type,
        const std::string& filename = "") const;

    /*
     * Extract text from a plain text buffer with encoding detection.
     */
    ExtractionResult ExtractPlainText(
        const uint8_t* data, size_t length,
        const std::string& filename = "") const;

    /*
     * Extract members from a ZIP archive (including Office XML).
     * Recursion depth is bounded by options.
     */
    std::vector<ExtractionResult> ExtractZip(
        const uint8_t* data, size_t length,
        const std::string& filename = "",
        int depth = 0) const;

    /*
     * Extract printable ASCII/Unicode strings from binary data.
     */
    ExtractionResult ExtractBinaryStrings(
        const uint8_t* data, size_t length,
        const std::string& filename = "") const;

private:
    /* Encoding detection */
    enum class Encoding {
        UTF8,
        UTF16_LE,
        UTF16_BE,
        UTF32_LE,
        UTF32_BE,
        Latin1,
        ASCII,
    };

    Encoding DetectEncoding(const uint8_t* data, size_t length) const;
    std::string ConvertToUTF8(const uint8_t* data, size_t length, Encoding enc) const;

    /* ZIP parsing (minimal, no libarchive dependency) */
    struct ZipEntry {
        std::string filename;
        uint32_t    compressed_size;
        uint32_t    uncompressed_size;
        uint16_t    compression_method;
        size_t      data_offset;     /* Offset to compressed data in archive */
    };

    std::vector<ZipEntry> ParseZipDirectory(const uint8_t* data, size_t length) const;
    std::vector<uint8_t> DecompressEntry(const uint8_t* data, size_t length,
                                          const ZipEntry& entry) const;

    ExtractionOptions options_;
    FileTypeDetector  detector_;
};

}  // namespace akeso::dlp
