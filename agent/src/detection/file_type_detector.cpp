/*
 * file_type_detector.cpp
 * AkesoDLP Agent - File Type Detection
 *
 * Custom magic byte signature table for 50+ file types.
 * No libmagic dependency. Handles compound formats like
 * ZIP-based Office documents by inspecting internal structure.
 */

#include "akeso/detection/file_type_detector.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_map>

namespace akeso::dlp {

/* ================================================================== */
/*  Construction                                                        */
/* ================================================================== */

FileTypeDetector::FileTypeDetector() {
    InitSignatures();
}

/* ================================================================== */
/*  Signature table                                                     */
/* ================================================================== */

void FileTypeDetector::InitSignatures() {
    signatures_.clear();

    /* Helper lambda */
    auto add = [this](std::vector<uint8_t> magic, size_t offset,
                      const char* name, const char* mime,
                      const char* ext, FileCategory cat, int conf) {
        signatures_.push_back({
            std::move(magic), offset,
            name, mime, ext, cat, conf
        });
    };

    /* ---- Documents ---- */
    add({0x25, 0x50, 0x44, 0x46}, 0,
        "PDF", "application/pdf", ".pdf", FileCategory::Document, 95);

    add({0x7B, 0x5C, 0x72, 0x74, 0x66}, 0,
        "RTF", "application/rtf", ".rtf", FileCategory::Document, 95);

    /* OLE2 Compound Document (doc/xls/ppt/msg) — differentiated later */
    add({0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 0,
        "OLE2 Compound", "application/x-ole-storage", ".doc", FileCategory::Document, 80);

    /* ---- ZIP-based (Office Open XML, ODF, JAR, APK) ---- */
    /* Detected as ZIP first, then refined in CheckCompoundFormats */
    add({0x50, 0x4B, 0x03, 0x04}, 0,
        "ZIP", "application/zip", ".zip", FileCategory::Archive, 70);

    /* ---- Images ---- */
    add({0xFF, 0xD8, 0xFF}, 0,
        "JPEG", "image/jpeg", ".jpg", FileCategory::Image, 95);

    add({0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0,
        "PNG", "image/png", ".png", FileCategory::Image, 95);

    add({0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, 0,
        "GIF87a", "image/gif", ".gif", FileCategory::Image, 95);

    add({0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, 0,
        "GIF89a", "image/gif", ".gif", FileCategory::Image, 95);

    add({0x42, 0x4D}, 0,
        "BMP", "image/bmp", ".bmp", FileCategory::Image, 85);

    /* TIFF (little-endian) */
    add({0x49, 0x49, 0x2A, 0x00}, 0,
        "TIFF", "image/tiff", ".tiff", FileCategory::Image, 95);

    /* TIFF (big-endian) */
    add({0x4D, 0x4D, 0x00, 0x2A}, 0,
        "TIFF", "image/tiff", ".tiff", FileCategory::Image, 95);

    /* WebP */
    add({0x52, 0x49, 0x46, 0x46}, 0,
        "RIFF", "application/octet-stream", ".riff", FileCategory::Unknown, 60);
    /* WebP is RIFF + "WEBP" at offset 8 — handled in CheckCompoundFormats */

    /* ICO */
    add({0x00, 0x00, 0x01, 0x00}, 0,
        "ICO", "image/x-icon", ".ico", FileCategory::Image, 85);

    /* PSD */
    add({0x38, 0x42, 0x50, 0x53}, 0,
        "PSD", "image/vnd.adobe.photoshop", ".psd", FileCategory::Image, 95);

    /* ---- Audio ---- */
    /* MP3 (ID3v2 tag) */
    add({0x49, 0x44, 0x33}, 0,
        "MP3", "audio/mpeg", ".mp3", FileCategory::Audio, 90);

    /* MP3 (sync word, frame header) */
    add({0xFF, 0xFB}, 0,
        "MP3", "audio/mpeg", ".mp3", FileCategory::Audio, 75);

    /* WAV (RIFF + WAVE) — handled in CheckCompoundFormats */

    /* FLAC */
    add({0x66, 0x4C, 0x61, 0x43}, 0,
        "FLAC", "audio/flac", ".flac", FileCategory::Audio, 95);

    /* OGG */
    add({0x4F, 0x67, 0x67, 0x53}, 0,
        "OGG", "audio/ogg", ".ogg", FileCategory::Audio, 90);

    /* AAC (ADTS) */
    add({0xFF, 0xF1}, 0,
        "AAC", "audio/aac", ".aac", FileCategory::Audio, 75);

    /* ---- Video ---- */
    /* AVI (RIFF + AVI) — handled in CheckCompoundFormats */

    /* MKV/WebM (Matroska) — refined in CheckCompoundFormats */
    add({0x1A, 0x45, 0xDF, 0xA3}, 0,
        "MKV", "video/x-matroska", ".mkv", FileCategory::Video, 85);

    /* FLV */
    add({0x46, 0x4C, 0x56, 0x01}, 0,
        "FLV", "video/x-flv", ".flv", FileCategory::Video, 95);

    /* MP4 (ftyp box) — check at offset 4 */
    add({0x66, 0x74, 0x79, 0x70}, 4,
        "MP4", "video/mp4", ".mp4", FileCategory::Video, 90);

    /* ---- Archives ---- */
    /* ZIP already added above */

    /* RAR v5 */
    add({0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, 0,
        "RAR5", "application/x-rar-compressed", ".rar", FileCategory::Archive, 95);

    /* RAR v4 */
    add({0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, 0,
        "RAR", "application/x-rar-compressed", ".rar", FileCategory::Archive, 95);

    /* 7z */
    add({0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 0,
        "7-Zip", "application/x-7z-compressed", ".7z", FileCategory::Archive, 95);

    /* TAR (ustar at offset 257) */
    add({0x75, 0x73, 0x74, 0x61, 0x72}, 257,
        "TAR", "application/x-tar", ".tar", FileCategory::Archive, 90);

    /* GZ */
    add({0x1F, 0x8B}, 0,
        "GZIP", "application/gzip", ".gz", FileCategory::Archive, 95);

    /* BZ2 */
    add({0x42, 0x5A, 0x68}, 0,
        "BZ2", "application/x-bzip2", ".bz2", FileCategory::Archive, 95);

    /* XZ */
    add({0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, 0,
        "XZ", "application/x-xz", ".xz", FileCategory::Archive, 95);

    /* ZSTD */
    add({0x28, 0xB5, 0x2F, 0xFD}, 0,
        "ZSTD", "application/zstd", ".zst", FileCategory::Archive, 95);

    /* ---- Executables ---- */
    /* PE (MZ header) */
    add({0x4D, 0x5A}, 0,
        "PE Executable", "application/x-dosexec", ".exe", FileCategory::Executable, 90);

    /* ELF */
    add({0x7F, 0x45, 0x4C, 0x46}, 0,
        "ELF", "application/x-elf", ".elf", FileCategory::Executable, 95);

    /* Mach-O (32-bit) */
    add({0xFE, 0xED, 0xFA, 0xCE}, 0,
        "Mach-O 32", "application/x-mach-binary", ".macho", FileCategory::Executable, 95);

    /* Mach-O (64-bit) */
    add({0xFE, 0xED, 0xFA, 0xCF}, 0,
        "Mach-O 64", "application/x-mach-binary", ".macho", FileCategory::Executable, 95);

    /* Mach-O (reverse byte order 32) */
    add({0xCE, 0xFA, 0xED, 0xFE}, 0,
        "Mach-O 32 (LE)", "application/x-mach-binary", ".macho", FileCategory::Executable, 95);

    /* Mach-O (reverse byte order 64) */
    add({0xCF, 0xFA, 0xED, 0xFE}, 0,
        "Mach-O 64 (LE)", "application/x-mach-binary", ".macho", FileCategory::Executable, 95);

    /* Mach-O Universal (Fat) */
    add({0xCA, 0xFE, 0xBA, 0xBE}, 0,
        "Mach-O Universal", "application/x-mach-binary", ".macho", FileCategory::Executable, 85);

    /* MSI (also OLE2, but has specific CLSID — handle in compound) */

    /* ---- Scripts ---- */
    /* Shebang */
    add({0x23, 0x21}, 0,
        "Script (Shebang)", "text/x-script", ".sh", FileCategory::Script, 70);

    /* ---- Database ---- */
    /* SQLite */
    add({0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66,
         0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, 0,
        "SQLite", "application/x-sqlite3", ".sqlite", FileCategory::Database, 95);

    /* MS Access (JET) */
    add({0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E,
         0x64, 0x61, 0x72, 0x64, 0x20, 0x4A, 0x65, 0x74}, 0,
        "MS Access", "application/x-msaccess", ".mdb", FileCategory::Database, 90);

    /* ---- Fonts ---- */
    /* TTF */
    add({0x00, 0x01, 0x00, 0x00, 0x00}, 0,
        "TrueType Font", "font/ttf", ".ttf", FileCategory::Font, 80);

    /* OTF */
    add({0x4F, 0x54, 0x54, 0x4F}, 0,
        "OpenType Font", "font/otf", ".otf", FileCategory::Font, 95);

    /* WOFF */
    add({0x77, 0x4F, 0x46, 0x46}, 0,
        "WOFF", "font/woff", ".woff", FileCategory::Font, 95);

    /* WOFF2 */
    add({0x77, 0x4F, 0x46, 0x32}, 0,
        "WOFF2", "font/woff2", ".woff2", FileCategory::Font, 95);

    /* ---- CAD ---- */
    /* DWG */
    add({0x41, 0x43, 0x31, 0x30}, 0,
        "DWG", "image/vnd.dwg", ".dwg", FileCategory::CAD, 95);

    /* ---- Email ---- */
    /* EML typically starts with headers — detected by name */

    /* ---- Additional formats ---- */

    /* WASM (WebAssembly) */
    add({0x00, 0x61, 0x73, 0x6D}, 0,
        "WebAssembly", "application/wasm", ".wasm", FileCategory::Executable, 95);

    /* LZ4 */
    add({0x04, 0x22, 0x4D, 0x18}, 0,
        "LZ4", "application/x-lz4", ".lz4", FileCategory::Archive, 95);

    /* Java class file */
    add({0xCA, 0xFE, 0xBA, 0xBE}, 0,
        "Java Class", "application/java-vm", ".class", FileCategory::Executable, 80);

    /* ISO 9660 CD image (offset 32769) */
    add({0x43, 0x44, 0x30, 0x30, 0x31}, 32769,
        "ISO 9660", "application/x-iso9660-image", ".iso", FileCategory::Archive, 90);

    /* Windows shortcut (LNK) */
    add({0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00}, 0,
        "LNK", "application/x-ms-shortcut", ".lnk", FileCategory::Executable, 90);

    /* PCX image */
    add({0x0A, 0x05, 0x01, 0x08}, 0,
        "PCX", "image/x-pcx", ".pcx", FileCategory::Image, 80);

    /* MIDI */
    add({0x4D, 0x54, 0x68, 0x64}, 0,
        "MIDI", "audio/midi", ".mid", FileCategory::Audio, 95);

    /* Sort by magic length descending for longest-match-first */
    std::sort(signatures_.begin(), signatures_.end(),
              [](const MagicSignature& a, const MagicSignature& b) {
                  return a.magic.size() > b.magic.size();
              });
}

/* ================================================================== */
/*  Content-based detection                                             */
/* ================================================================== */

FileTypeResult FileTypeDetector::DetectFromContent(const uint8_t* data, size_t length) const {
    if (!data || length == 0) {
        return {"Unknown", "application/octet-stream", "", FileCategory::Unknown, 0};
    }

    FileTypeResult best{"Unknown", "application/octet-stream", "", FileCategory::Unknown, 0};

    /* Check each signature */
    for (const auto& sig : signatures_) {
        if (sig.offset + sig.magic.size() > length) continue;

        if (std::memcmp(data + sig.offset, sig.magic.data(), sig.magic.size()) == 0) {
            if (sig.confidence > best.confidence) {
                best.type_name  = sig.type_name;
                best.mime_type  = sig.mime_type;
                best.extension  = sig.extension;
                best.category   = sig.category;
                best.confidence = sig.confidence;
            }
        }
    }

    /* Refine compound formats (ZIP→Office, RIFF→WAV/AVI/WebP, etc.) */
    auto compound = CheckCompoundFormats(data, length);
    if (compound.confidence > best.confidence) {
        best = compound;
    }

    return best;
}

FileTypeResult FileTypeDetector::DetectFromContent(const char* data, size_t length) const {
    return DetectFromContent(reinterpret_cast<const uint8_t*>(data), length);
}

/* ================================================================== */
/*  Compound format refinement                                          */
/* ================================================================== */

FileTypeResult FileTypeDetector::CheckCompoundFormats(const uint8_t* data, size_t length) const {
    FileTypeResult result{"Unknown", "application/octet-stream", "", FileCategory::Unknown, 0};

    /* ---- ZIP-based Office formats ---- */
    if (length >= 4 && data[0] == 0x50 && data[1] == 0x4B &&
        data[2] == 0x03 && data[3] == 0x04) {

        /* Search for internal file names that identify the Office type.
         * ZIP local file headers contain the filename; look for known
         * paths within first 8KB of the file. */
        std::string_view content(reinterpret_cast<const char*>(data),
                                 std::min(length, static_cast<size_t>(8192)));

        if (content.find("word/") != std::string_view::npos) {
            return {"DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    ".docx", FileCategory::Document, 95};
        }
        if (content.find("xl/") != std::string_view::npos) {
            return {"XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    ".xlsx", FileCategory::Spreadsheet, 95};
        }
        if (content.find("ppt/") != std::string_view::npos) {
            return {"PPTX", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    ".pptx", FileCategory::Presentation, 95};
        }
        if (content.find("META-INF/") != std::string_view::npos) {
            if (content.find("classes.dex") != std::string_view::npos) {
                return {"APK", "application/vnd.android.package-archive",
                        ".apk", FileCategory::Archive, 90};
            }
            return {"JAR", "application/java-archive", ".jar", FileCategory::Archive, 85};
        }
        if (content.find("mimetype") != std::string_view::npos) {
            /* ODF: check mimetype content */
            if (content.find("application/vnd.oasis.opendocument.text") != std::string_view::npos) {
                return {"ODT", "application/vnd.oasis.opendocument.text",
                        ".odt", FileCategory::Document, 95};
            }
            if (content.find("application/vnd.oasis.opendocument.spreadsheet") != std::string_view::npos) {
                return {"ODS", "application/vnd.oasis.opendocument.spreadsheet",
                        ".ods", FileCategory::Spreadsheet, 95};
            }
            if (content.find("application/vnd.oasis.opendocument.presentation") != std::string_view::npos) {
                return {"ODP", "application/vnd.oasis.opendocument.presentation",
                        ".odp", FileCategory::Presentation, 95};
            }
        }
        /* Remains as generic ZIP */
    }

    /* ---- RIFF-based formats ---- */
    if (length >= 12 && data[0] == 0x52 && data[1] == 0x49 &&
        data[2] == 0x46 && data[3] == 0x46) {

        std::string_view fourcc(reinterpret_cast<const char*>(data + 8), 4);

        if (fourcc == "WEBP") {
            return {"WebP", "image/webp", ".webp", FileCategory::Image, 95};
        }
        if (fourcc == "WAVE") {
            return {"WAV", "audio/wav", ".wav", FileCategory::Audio, 95};
        }
        if (fourcc == "AVI ") {
            return {"AVI", "video/x-msvideo", ".avi", FileCategory::Video, 95};
        }
    }

    /* ---- Matroska vs WebM ---- */
    if (length >= 4 && data[0] == 0x1A && data[1] == 0x45 &&
        data[2] == 0xDF && data[3] == 0xA3) {

        /* Search for DocType in first 64 bytes */
        std::string_view header(reinterpret_cast<const char*>(data),
                                std::min(length, static_cast<size_t>(64)));
        if (header.find("webm") != std::string_view::npos) {
            return {"WebM", "video/webm", ".webm", FileCategory::Video, 95};
        }
        /* Default to MKV */
        return {"MKV", "video/x-matroska", ".mkv", FileCategory::Video, 90};
    }

    return result;
}

/* ================================================================== */
/*  Name-based detection                                                */
/* ================================================================== */

FileTypeResult FileTypeDetector::DetectFromName(std::string_view filename) const {
    std::string ext = GetExtension(filename);
    if (ext.empty()) {
        return {"Unknown", "application/octet-stream", "", FileCategory::Unknown, 0};
    }

    /* Extension to type mapping */
    static const std::unordered_map<std::string, FileTypeResult> ext_map = {
        /* Documents */
        {".pdf",   {"PDF",  "application/pdf", ".pdf", FileCategory::Document, 50}},
        {".doc",   {"DOC",  "application/msword", ".doc", FileCategory::Document, 50}},
        {".docx",  {"DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx", FileCategory::Document, 50}},
        {".rtf",   {"RTF",  "application/rtf", ".rtf", FileCategory::Document, 50}},
        {".txt",   {"Text", "text/plain", ".txt", FileCategory::Document, 40}},
        {".odt",   {"ODT",  "application/vnd.oasis.opendocument.text", ".odt", FileCategory::Document, 50}},

        /* Spreadsheets */
        {".xls",   {"XLS",  "application/vnd.ms-excel", ".xls", FileCategory::Spreadsheet, 50}},
        {".xlsx",  {"XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx", FileCategory::Spreadsheet, 50}},
        {".csv",   {"CSV",  "text/csv", ".csv", FileCategory::Spreadsheet, 40}},
        {".ods",   {"ODS",  "application/vnd.oasis.opendocument.spreadsheet", ".ods", FileCategory::Spreadsheet, 50}},

        /* Presentations */
        {".ppt",   {"PPT",  "application/vnd.ms-powerpoint", ".ppt", FileCategory::Presentation, 50}},
        {".pptx",  {"PPTX", "application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx", FileCategory::Presentation, 50}},
        {".odp",   {"ODP",  "application/vnd.oasis.opendocument.presentation", ".odp", FileCategory::Presentation, 50}},

        /* Images */
        {".jpg",   {"JPEG", "image/jpeg", ".jpg", FileCategory::Image, 50}},
        {".jpeg",  {"JPEG", "image/jpeg", ".jpeg", FileCategory::Image, 50}},
        {".png",   {"PNG",  "image/png", ".png", FileCategory::Image, 50}},
        {".gif",   {"GIF",  "image/gif", ".gif", FileCategory::Image, 50}},
        {".bmp",   {"BMP",  "image/bmp", ".bmp", FileCategory::Image, 50}},
        {".tiff",  {"TIFF", "image/tiff", ".tiff", FileCategory::Image, 50}},
        {".tif",   {"TIFF", "image/tiff", ".tif", FileCategory::Image, 50}},
        {".webp",  {"WebP", "image/webp", ".webp", FileCategory::Image, 50}},
        {".ico",   {"ICO",  "image/x-icon", ".ico", FileCategory::Image, 50}},
        {".svg",   {"SVG",  "image/svg+xml", ".svg", FileCategory::Image, 50}},
        {".psd",   {"PSD",  "image/vnd.adobe.photoshop", ".psd", FileCategory::Image, 50}},

        /* Audio */
        {".mp3",   {"MP3",  "audio/mpeg", ".mp3", FileCategory::Audio, 50}},
        {".wav",   {"WAV",  "audio/wav", ".wav", FileCategory::Audio, 50}},
        {".flac",  {"FLAC", "audio/flac", ".flac", FileCategory::Audio, 50}},
        {".ogg",   {"OGG",  "audio/ogg", ".ogg", FileCategory::Audio, 50}},
        {".aac",   {"AAC",  "audio/aac", ".aac", FileCategory::Audio, 50}},
        {".m4a",   {"M4A",  "audio/mp4", ".m4a", FileCategory::Audio, 50}},
        {".wma",   {"WMA",  "audio/x-ms-wma", ".wma", FileCategory::Audio, 50}},

        /* Video */
        {".mp4",   {"MP4",  "video/mp4", ".mp4", FileCategory::Video, 50}},
        {".avi",   {"AVI",  "video/x-msvideo", ".avi", FileCategory::Video, 50}},
        {".mkv",   {"MKV",  "video/x-matroska", ".mkv", FileCategory::Video, 50}},
        {".mov",   {"MOV",  "video/quicktime", ".mov", FileCategory::Video, 50}},
        {".webm",  {"WebM", "video/webm", ".webm", FileCategory::Video, 50}},
        {".flv",   {"FLV",  "video/x-flv", ".flv", FileCategory::Video, 50}},
        {".wmv",   {"WMV",  "video/x-ms-wmv", ".wmv", FileCategory::Video, 50}},

        /* Archives */
        {".zip",   {"ZIP",  "application/zip", ".zip", FileCategory::Archive, 50}},
        {".rar",   {"RAR",  "application/x-rar-compressed", ".rar", FileCategory::Archive, 50}},
        {".7z",    {"7-Zip","application/x-7z-compressed", ".7z", FileCategory::Archive, 50}},
        {".tar",   {"TAR",  "application/x-tar", ".tar", FileCategory::Archive, 50}},
        {".gz",    {"GZIP", "application/gzip", ".gz", FileCategory::Archive, 50}},
        {".bz2",   {"BZ2",  "application/x-bzip2", ".bz2", FileCategory::Archive, 50}},
        {".xz",    {"XZ",   "application/x-xz", ".xz", FileCategory::Archive, 50}},
        {".zst",   {"ZSTD", "application/zstd", ".zst", FileCategory::Archive, 50}},

        /* Executables */
        {".exe",   {"PE Executable", "application/x-dosexec", ".exe", FileCategory::Executable, 50}},
        {".dll",   {"DLL",  "application/x-dosexec", ".dll", FileCategory::Executable, 50}},
        {".sys",   {"SYS Driver", "application/x-dosexec", ".sys", FileCategory::Executable, 50}},
        {".msi",   {"MSI",  "application/x-msi", ".msi", FileCategory::Executable, 50}},

        /* Scripts */
        {".py",    {"Python", "text/x-python", ".py", FileCategory::Script, 50}},
        {".js",    {"JavaScript", "text/javascript", ".js", FileCategory::Script, 50}},
        {".ps1",   {"PowerShell", "text/x-powershell", ".ps1", FileCategory::Script, 50}},
        {".bat",   {"Batch", "text/x-batch", ".bat", FileCategory::Script, 50}},
        {".cmd",   {"Batch", "text/x-batch", ".cmd", FileCategory::Script, 50}},
        {".sh",    {"Shell", "text/x-shellscript", ".sh", FileCategory::Script, 50}},
        {".vbs",   {"VBScript", "text/x-vbscript", ".vbs", FileCategory::Script, 50}},

        /* Database */
        {".sqlite",{"SQLite", "application/x-sqlite3", ".sqlite", FileCategory::Database, 50}},
        {".db",    {"Database", "application/x-sqlite3", ".db", FileCategory::Database, 40}},
        {".mdb",   {"MS Access", "application/x-msaccess", ".mdb", FileCategory::Database, 50}},

        /* Fonts */
        {".ttf",   {"TrueType Font", "font/ttf", ".ttf", FileCategory::Font, 50}},
        {".otf",   {"OpenType Font", "font/otf", ".otf", FileCategory::Font, 50}},
        {".woff",  {"WOFF", "font/woff", ".woff", FileCategory::Font, 50}},
        {".woff2", {"WOFF2","font/woff2", ".woff2", FileCategory::Font, 50}},

        /* CAD */
        {".dwg",   {"DWG", "image/vnd.dwg", ".dwg", FileCategory::CAD, 50}},

        /* Email */
        {".eml",   {"EML", "message/rfc822", ".eml", FileCategory::Email, 50}},
        {".msg",   {"MSG", "application/vnd.ms-outlook", ".msg", FileCategory::Email, 50}},
    };

    auto it = ext_map.find(ext);
    if (it != ext_map.end()) {
        return it->second;
    }

    return {"Unknown", "application/octet-stream", ext, FileCategory::Unknown, 0};
}

/* ================================================================== */
/*  Combined detection                                                  */
/* ================================================================== */

FileTypeResult FileTypeDetector::Detect(const uint8_t* data, size_t length,
                                         std::string_view filename) const {
    auto content_result = DetectFromContent(data, length);
    auto name_result = DetectFromName(filename);

    /* Content-based wins if it has reasonable confidence */
    if (content_result.confidence >= 70) {
        /* Boost if name agrees */
        if (name_result.type_name == content_result.type_name ||
            name_result.category == content_result.category) {
            content_result.confidence = std::min(100, content_result.confidence + 5);
        }
        return content_result;
    }

    /* If content is weak but name is known, use name but flag lower confidence */
    if (name_result.confidence > 0 && name_result.category != FileCategory::Unknown) {
        return name_result;
    }

    /* Return whatever we have */
    return (content_result.confidence > 0) ? content_result : name_result;
}

/* ================================================================== */
/*  Utilities                                                           */
/* ================================================================== */

std::string FileTypeDetector::ToLower(std::string_view s) {
    std::string result(s);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

std::string FileTypeDetector::GetExtension(std::string_view filename) {
    auto dot = filename.rfind('.');
    if (dot == std::string_view::npos || dot == filename.size() - 1) {
        return "";
    }
    return ToLower(filename.substr(dot));
}

}  // namespace akeso::dlp
