/*
 * file_type_detector.h
 * AkesoDLP Agent - File Type Detection
 *
 * Magic byte signature matching for 50+ file types.
 * No external dependency (no libmagic). Custom signature table
 * covers Office, PDF, images, archives, executables, and scripts.
 *
 * Also supports file size thresholds and name pattern matching.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  File categories                                                     */
/* ------------------------------------------------------------------ */

enum class FileCategory {
    Unknown,
    Document,       /* PDF, Office, RTF, plain text */
    Spreadsheet,    /* Excel, CSV */
    Presentation,   /* PowerPoint */
    Image,          /* JPEG, PNG, GIF, BMP, TIFF, WebP, ICO, SVG */
    Audio,          /* MP3, WAV, FLAC, OGG, AAC */
    Video,          /* MP4, AVI, MKV, MOV, WebM, FLV */
    Archive,        /* ZIP, RAR, 7z, TAR, GZ, BZ2, XZ, ZSTD */
    Executable,     /* PE, ELF, Mach-O, DLL, MSI */
    Script,         /* Python, JavaScript, PowerShell, Batch, Shell */
    Database,       /* SQLite, MDB */
    Font,           /* TTF, OTF, WOFF, WOFF2 */
    CAD,            /* DWG */
    Email,          /* EML, MSG */
};

/* ------------------------------------------------------------------ */
/*  Detection result                                                    */
/* ------------------------------------------------------------------ */

struct FileTypeResult {
    std::string   type_name;       /* e.g. "PDF", "JPEG", "PE Executable" */
    std::string   mime_type;       /* e.g. "application/pdf" */
    std::string   extension;       /* e.g. ".pdf" (canonical) */
    FileCategory  category = FileCategory::Unknown;
    int           confidence = 0;  /* 0-100 */
};

/* ------------------------------------------------------------------ */
/*  Magic signature entry (internal)                                    */
/* ------------------------------------------------------------------ */

struct MagicSignature {
    std::vector<uint8_t> magic;       /* Byte sequence to match */
    size_t               offset;      /* Offset into file */
    std::string          type_name;
    std::string          mime_type;
    std::string          extension;
    FileCategory         category;
    int                  confidence;  /* Base confidence for this sig */
};

/* ------------------------------------------------------------------ */
/*  FileTypeDetector                                                    */
/* ------------------------------------------------------------------ */

class FileTypeDetector {
public:
    FileTypeDetector();

    /*
     * Detect file type from content bytes.
     * Reads magic bytes from the buffer (first N bytes are sufficient;
     * typically 16-64 bytes, up to 8192 for compound formats).
     */
    FileTypeResult DetectFromContent(const uint8_t* data, size_t length) const;
    FileTypeResult DetectFromContent(const char* data, size_t length) const;

    /*
     * Detect file type from file name/extension.
     * Lower confidence than content-based detection.
     */
    FileTypeResult DetectFromName(std::string_view filename) const;

    /*
     * Combined detection: content first, name as fallback/boost.
     */
    FileTypeResult Detect(const uint8_t* data, size_t length,
                          std::string_view filename) const;

    /* Number of registered signatures */
    size_t SignatureCount() const { return signatures_.size(); }

private:
    void InitSignatures();
    FileTypeResult CheckCompoundFormats(const uint8_t* data, size_t length) const;
    static std::string ToLower(std::string_view s);
    static std::string GetExtension(std::string_view filename);

    std::vector<MagicSignature> signatures_;
};

}  // namespace akeso::dlp
