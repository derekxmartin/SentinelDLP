/*
 * content_extractor.cpp
 * AkesoDLP Agent - Content Extraction
 *
 * Plain text encoding detection (BOM + heuristic), ZIP archive
 * extraction via zlib inflate, and binary string extraction.
 */

#include "akeso/detection/content_extractor.h"

#include <algorithm>
#include <cstring>

#include <zlib.h>

namespace akeso::dlp {

/* ================================================================== */
/*  Construction                                                        */
/* ================================================================== */

ContentExtractor::ContentExtractor(const ExtractionOptions& opts)
    : options_(opts)
{
}

/* ================================================================== */
/*  Main extraction dispatch                                            */
/* ================================================================== */

std::vector<ExtractionResult> ContentExtractor::Extract(
    const uint8_t* data, size_t length,
    const FileTypeResult& file_type,
    const std::string& filename) const
{
    if (!data || length == 0) {
        return {{false, "", "Empty input", filename, FileCategory::Unknown}};
    }

    /* Cap input size */
    if (length > options_.max_text_size) {
        length = options_.max_text_size;
    }

    switch (file_type.category) {
    case FileCategory::Document:
    case FileCategory::Script:
    case FileCategory::Email:
        /* Plain text or text-like formats */
        if (file_type.type_name == "Text" || file_type.type_name == "CSV" ||
            file_type.category == FileCategory::Script ||
            file_type.type_name == "EML" ||
            file_type.type_name == "RTF") {
            return {ExtractPlainText(data, length, filename)};
        }
        /* Office XML (DOCX/XLSX/PPTX) — extract ZIP members */
        if (file_type.type_name == "DOCX" || file_type.type_name == "XLSX" ||
            file_type.type_name == "PPTX" || file_type.type_name == "ODT" ||
            file_type.type_name == "ODS"  || file_type.type_name == "ODP") {
            return ExtractZip(data, length, filename);
        }
        /* PDF and OLE2 — extract binary strings as fallback */
        return {ExtractBinaryStrings(data, length, filename)};

    case FileCategory::Spreadsheet:
        if (file_type.type_name == "CSV") {
            return {ExtractPlainText(data, length, filename)};
        }
        if (file_type.type_name == "XLSX" || file_type.type_name == "ODS") {
            return ExtractZip(data, length, filename);
        }
        return {ExtractBinaryStrings(data, length, filename)};

    case FileCategory::Presentation:
        if (file_type.type_name == "PPTX" || file_type.type_name == "ODP") {
            return ExtractZip(data, length, filename);
        }
        return {ExtractBinaryStrings(data, length, filename)};

    case FileCategory::Archive:
        if (file_type.type_name == "ZIP" || file_type.type_name == "JAR" ||
            file_type.type_name == "APK") {
            return ExtractZip(data, length, filename);
        }
        /* Other archives: extract binary strings */
        return {ExtractBinaryStrings(data, length, filename)};

    default:
        /* Binary formats: extract printable strings */
        return {ExtractBinaryStrings(data, length, filename)};
    }
}

std::vector<ExtractionResult> ContentExtractor::Extract(
    const char* data, size_t length,
    const FileTypeResult& file_type,
    const std::string& filename) const
{
    return Extract(reinterpret_cast<const uint8_t*>(data), length, file_type, filename);
}

/* ================================================================== */
/*  Plain text extraction with encoding detection                       */
/* ================================================================== */

ContentExtractor::Encoding ContentExtractor::DetectEncoding(
    const uint8_t* data, size_t length) const
{
    if (length == 0) return Encoding::ASCII;

    /* BOM detection */
    if (length >= 4 && data[0] == 0xFF && data[1] == 0xFE &&
        data[2] == 0x00 && data[3] == 0x00) {
        return Encoding::UTF32_LE;
    }
    if (length >= 4 && data[0] == 0x00 && data[1] == 0x00 &&
        data[2] == 0xFE && data[3] == 0xFF) {
        return Encoding::UTF32_BE;
    }
    if (length >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        return Encoding::UTF16_LE;
    }
    if (length >= 2 && data[0] == 0xFE && data[1] == 0xFF) {
        return Encoding::UTF16_BE;
    }
    if (length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
        return Encoding::UTF8;
    }

    /* Heuristic: check for UTF-16 by looking for null bytes in pattern */
    if (length >= 4) {
        int null_even = 0;
        int null_odd = 0;
        size_t check_len = std::min(length, static_cast<size_t>(256));
        for (size_t i = 0; i < check_len - 1; i += 2) {
            if (data[i] == 0 && data[i + 1] != 0) ++null_even;
            if (data[i] != 0 && data[i + 1] == 0) ++null_odd;
        }
        /* If ~half the bytes are null in a pattern, likely UTF-16 */
        if (null_even > static_cast<int>(check_len / 6)) return Encoding::UTF16_BE;
        if (null_odd > static_cast<int>(check_len / 6)) return Encoding::UTF16_LE;
    }

    /* Heuristic: check for valid UTF-8 multi-byte sequences */
    bool has_high_bytes = false;
    bool valid_utf8 = true;
    size_t i = 0;
    size_t check_len = std::min(length, static_cast<size_t>(4096));

    while (i < check_len) {
        uint8_t b = data[i];
        if (b <= 0x7F) {
            ++i;
            continue;
        }
        has_high_bytes = true;

        /* Determine expected continuation bytes */
        int cont = 0;
        if ((b & 0xE0) == 0xC0) cont = 1;
        else if ((b & 0xF0) == 0xE0) cont = 2;
        else if ((b & 0xF8) == 0xF0) cont = 3;
        else { valid_utf8 = false; break; }

        /* Verify continuation bytes */
        for (int j = 0; j < cont && i + 1 + j < check_len; ++j) {
            if ((data[i + 1 + j] & 0xC0) != 0x80) {
                valid_utf8 = false;
                break;
            }
        }
        if (!valid_utf8) break;
        i += 1 + cont;
    }

    if (has_high_bytes && valid_utf8) return Encoding::UTF8;
    if (has_high_bytes && !valid_utf8) return Encoding::Latin1;
    return Encoding::ASCII;
}

std::string ContentExtractor::ConvertToUTF8(
    const uint8_t* data, size_t length, Encoding enc) const
{
    switch (enc) {
    case Encoding::ASCII:
    case Encoding::UTF8:
    {
        /* Skip BOM if present */
        size_t start = 0;
        if (length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
            start = 3;
        }
        return std::string(reinterpret_cast<const char*>(data + start), length - start);
    }

    case Encoding::UTF16_LE:
    {
        std::string result;
        size_t start = 0;
        /* Skip BOM */
        if (length >= 2 && data[0] == 0xFF && data[1] == 0xFE) start = 2;

        for (size_t i = start; i + 1 < length; i += 2) {
            uint16_t cp = static_cast<uint16_t>(data[i]) |
                          (static_cast<uint16_t>(data[i + 1]) << 8);

            if (cp <= 0x7F) {
                result += static_cast<char>(cp);
            } else if (cp <= 0x7FF) {
                result += static_cast<char>(0xC0 | (cp >> 6));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
                /* Surrogate pair handling omitted — treat as BMP */
                result += static_cast<char>(0xE0 | (cp >> 12));
                result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            }
        }
        return result;
    }

    case Encoding::UTF16_BE:
    {
        std::string result;
        size_t start = 0;
        if (length >= 2 && data[0] == 0xFE && data[1] == 0xFF) start = 2;

        for (size_t i = start; i + 1 < length; i += 2) {
            uint16_t cp = (static_cast<uint16_t>(data[i]) << 8) |
                           static_cast<uint16_t>(data[i + 1]);

            if (cp <= 0x7F) {
                result += static_cast<char>(cp);
            } else if (cp <= 0x7FF) {
                result += static_cast<char>(0xC0 | (cp >> 6));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
                result += static_cast<char>(0xE0 | (cp >> 12));
                result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            }
        }
        return result;
    }

    case Encoding::UTF32_LE:
    {
        std::string result;
        size_t start = 0;
        if (length >= 4 && data[0] == 0xFF && data[1] == 0xFE &&
            data[2] == 0x00 && data[3] == 0x00) start = 4;

        for (size_t i = start; i + 3 < length; i += 4) {
            uint32_t cp = static_cast<uint32_t>(data[i]) |
                          (static_cast<uint32_t>(data[i + 1]) << 8) |
                          (static_cast<uint32_t>(data[i + 2]) << 16) |
                          (static_cast<uint32_t>(data[i + 3]) << 24);

            if (cp <= 0x7F) {
                result += static_cast<char>(cp);
            } else if (cp <= 0x7FF) {
                result += static_cast<char>(0xC0 | (cp >> 6));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            } else if (cp <= 0xFFFF) {
                result += static_cast<char>(0xE0 | (cp >> 12));
                result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            } else if (cp <= 0x10FFFF) {
                result += static_cast<char>(0xF0 | (cp >> 18));
                result += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            }
        }
        return result;
    }

    case Encoding::UTF32_BE:
    {
        std::string result;
        size_t start = 0;
        if (length >= 4 && data[0] == 0x00 && data[1] == 0x00 &&
            data[2] == 0xFE && data[3] == 0xFF) start = 4;

        for (size_t i = start; i + 3 < length; i += 4) {
            uint32_t cp = (static_cast<uint32_t>(data[i]) << 24) |
                          (static_cast<uint32_t>(data[i + 1]) << 16) |
                          (static_cast<uint32_t>(data[i + 2]) << 8) |
                           static_cast<uint32_t>(data[i + 3]);

            if (cp <= 0x7F) {
                result += static_cast<char>(cp);
            } else if (cp <= 0x7FF) {
                result += static_cast<char>(0xC0 | (cp >> 6));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            } else if (cp <= 0xFFFF) {
                result += static_cast<char>(0xE0 | (cp >> 12));
                result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            } else if (cp <= 0x10FFFF) {
                result += static_cast<char>(0xF0 | (cp >> 18));
                result += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (cp & 0x3F));
            }
        }
        return result;
    }

    case Encoding::Latin1:
    {
        /* Latin-1 → UTF-8: bytes 0x80-0xFF become 2-byte sequences */
        std::string result;
        result.reserve(length + length / 4);
        for (size_t i = 0; i < length; ++i) {
            uint8_t b = data[i];
            if (b <= 0x7F) {
                result += static_cast<char>(b);
            } else {
                result += static_cast<char>(0xC0 | (b >> 6));
                result += static_cast<char>(0x80 | (b & 0x3F));
            }
        }
        return result;
    }
    }

    return std::string(reinterpret_cast<const char*>(data), length);
}

ExtractionResult ContentExtractor::ExtractPlainText(
    const uint8_t* data, size_t length, const std::string& filename) const
{
    if (!data || length == 0) {
        return {false, "", "Empty input", filename, FileCategory::Document};
    }

    Encoding enc = DetectEncoding(data, length);
    std::string text = ConvertToUTF8(data, length, enc);

    if (text.size() > options_.max_text_size) {
        text.resize(options_.max_text_size);
    }

    return {true, std::move(text), "", filename, FileCategory::Document};
}

/* ================================================================== */
/*  ZIP extraction (minimal parser, zlib inflate)                       */
/* ================================================================== */

std::vector<ContentExtractor::ZipEntry> ContentExtractor::ParseZipDirectory(
    const uint8_t* data, size_t length) const
{
    std::vector<ZipEntry> entries;

    /* Scan for local file headers (PK\x03\x04) */
    size_t pos = 0;
    while (pos + 30 <= length &&
           entries.size() < static_cast<size_t>(options_.max_zip_entries)) {

        /* Check local file header signature */
        if (data[pos] != 0x50 || data[pos + 1] != 0x4B ||
            data[pos + 2] != 0x03 || data[pos + 3] != 0x04) {
            break;  /* No more local headers */
        }

        uint16_t compression = static_cast<uint16_t>(data[pos + 8]) |
                               (static_cast<uint16_t>(data[pos + 9]) << 8);
        uint32_t comp_size   = static_cast<uint32_t>(data[pos + 18]) |
                               (static_cast<uint32_t>(data[pos + 19]) << 8) |
                               (static_cast<uint32_t>(data[pos + 20]) << 16) |
                               (static_cast<uint32_t>(data[pos + 21]) << 24);
        uint32_t uncomp_size = static_cast<uint32_t>(data[pos + 22]) |
                               (static_cast<uint32_t>(data[pos + 23]) << 8) |
                               (static_cast<uint32_t>(data[pos + 24]) << 16) |
                               (static_cast<uint32_t>(data[pos + 25]) << 24);
        uint16_t name_len    = static_cast<uint16_t>(data[pos + 26]) |
                               (static_cast<uint16_t>(data[pos + 27]) << 8);
        uint16_t extra_len   = static_cast<uint16_t>(data[pos + 28]) |
                               (static_cast<uint16_t>(data[pos + 29]) << 8);

        size_t header_end = pos + 30 + name_len + extra_len;
        if (header_end > length) break;

        std::string name(reinterpret_cast<const char*>(data + pos + 30), name_len);
        size_t data_offset = header_end;

        /* Skip directories and empty entries */
        if (!name.empty() && name.back() != '/' && comp_size > 0) {
            /* Bounds check */
            if (data_offset + comp_size <= length) {
                entries.push_back({
                    std::move(name), comp_size, uncomp_size,
                    compression, data_offset
                });
            }
        }

        pos = data_offset + comp_size;
    }

    return entries;
}

std::vector<uint8_t> ContentExtractor::DecompressEntry(
    const uint8_t* data, size_t length,
    const ZipEntry& entry) const
{
    if (entry.data_offset + entry.compressed_size > length) {
        return {};
    }

    const uint8_t* comp_data = data + entry.data_offset;

    if (entry.compression_method == 0) {
        /* Stored (no compression) */
        return {comp_data, comp_data + entry.compressed_size};
    }

    if (entry.compression_method == 8) {
        /* Deflate */
        size_t out_size = entry.uncompressed_size;
        if (out_size > options_.max_zip_entry) out_size = options_.max_zip_entry;

        std::vector<uint8_t> output(out_size);

        z_stream strm{};
        strm.next_in = const_cast<Bytef*>(comp_data);
        strm.avail_in = entry.compressed_size;
        strm.next_out = output.data();
        strm.avail_out = static_cast<uInt>(output.size());

        /* -MAX_WBITS = raw deflate (no zlib/gzip header) */
        if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
            return {};
        }

        int ret = inflate(&strm, Z_FINISH);
        size_t decompressed = strm.total_out;
        inflateEnd(&strm);

        if (ret != Z_STREAM_END && ret != Z_OK) {
            return {};
        }

        output.resize(decompressed);
        return output;
    }

    /* Unsupported compression method */
    return {};
}

std::vector<ExtractionResult> ContentExtractor::ExtractZip(
    const uint8_t* data, size_t length,
    const std::string& filename, int depth) const
{
    std::vector<ExtractionResult> results;

    if (!data || length == 0) {
        results.push_back({false, "", "Empty input", filename, FileCategory::Archive});
        return results;
    }

    if (depth >= options_.max_zip_depth) {
        results.push_back({false, "", "Max ZIP nesting depth reached",
                           filename, FileCategory::Archive});
        return results;
    }

    auto entries = ParseZipDirectory(data, length);
    if (entries.empty()) {
        results.push_back({false, "", "No extractable entries in ZIP",
                           filename, FileCategory::Archive});
        return results;
    }

    for (const auto& entry : entries) {
        auto decompressed = DecompressEntry(data, length, entry);
        if (decompressed.empty()) continue;

        /* Detect the type of the decompressed content */
        auto member_type = detector_.DetectFromContent(
            decompressed.data(), decompressed.size());
        if (member_type.category == FileCategory::Unknown) {
            member_type = detector_.DetectFromName(entry.filename);
        }

        std::string member_name = filename.empty()
            ? entry.filename
            : filename + "/" + entry.filename;

        /* Recurse into nested ZIPs */
        if (member_type.category == FileCategory::Archive &&
            (member_type.type_name == "ZIP" || member_type.type_name == "JAR")) {
            auto nested = ExtractZip(decompressed.data(), decompressed.size(),
                                     member_name, depth + 1);
            results.insert(results.end(), nested.begin(), nested.end());
            continue;
        }

        /* Extract text from member based on type */
        if (member_type.category == FileCategory::Document ||
            member_type.category == FileCategory::Script ||
            member_type.category == FileCategory::Spreadsheet) {

            /* Check if it's a text-like XML file (common in Office docs) */
            bool is_text = false;
            if (entry.filename.size() > 4) {
                std::string ext = entry.filename.substr(entry.filename.rfind('.') + 1);
                std::transform(ext.begin(), ext.end(), ext.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                is_text = (ext == "xml" || ext == "txt" || ext == "csv" ||
                           ext == "py" || ext == "js" || ext == "ps1" ||
                           ext == "sh" || ext == "html" || ext == "htm" ||
                           ext == "json" || ext == "yaml" || ext == "yml" ||
                           ext == "rels");
            }

            if (is_text || member_type.category == FileCategory::Script) {
                auto r = ExtractPlainText(decompressed.data(), decompressed.size(),
                                          member_name);
                if (r.success && !r.text.empty()) {
                    results.push_back(std::move(r));
                }
                continue;
            }
        }

        /* Default: extract binary strings */
        auto r = ExtractBinaryStrings(decompressed.data(), decompressed.size(),
                                      member_name);
        if (r.success && !r.text.empty()) {
            results.push_back(std::move(r));
        }
    }

    return results;
}

/* ================================================================== */
/*  Binary string extraction                                            */
/* ================================================================== */

ExtractionResult ContentExtractor::ExtractBinaryStrings(
    const uint8_t* data, size_t length, const std::string& filename) const
{
    if (!data || length == 0) {
        return {false, "", "Empty input", filename, FileCategory::Unknown};
    }

    std::string text;
    text.reserve(length / 4);  /* Rough estimate */

    std::string current_run;
    for (size_t i = 0; i < length && text.size() < options_.max_text_size; ++i) {
        uint8_t b = data[i];
        /* Printable ASCII + common whitespace */
        if ((b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\r' || b == '\t') {
            current_run += static_cast<char>(b);
        } else {
            if (current_run.size() >= options_.min_string_run) {
                text += current_run;
                text += '\n';
            }
            current_run.clear();
        }
    }
    /* Flush last run */
    if (current_run.size() >= options_.min_string_run) {
        text += current_run;
    }

    if (text.empty()) {
        return {false, "", "No extractable strings", filename, FileCategory::Unknown};
    }

    return {true, std::move(text), "", filename, FileCategory::Unknown};
}

}  // namespace akeso::dlp
