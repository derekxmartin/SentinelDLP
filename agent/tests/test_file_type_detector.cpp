/*
 * test_file_type_detector.cpp
 * AkesoDLP Agent - File Type Detector Tests
 *
 * Tests: magic byte signatures, compound formats (ZIP→Office, RIFF→WAV/AVI/WebP),
 *        renamed file detection, name-based fallback, combined detection.
 */

#include "akeso/detection/file_type_detector.h"

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

using namespace akeso::dlp;

/* ================================================================== */
/*  Fixture                                                             */
/* ================================================================== */

class FileTypeDetectorTest : public ::testing::Test {
protected:
    FileTypeDetector detector_;

    /* Helper: create a buffer with magic bytes */
    std::vector<uint8_t> MakeBuffer(std::initializer_list<uint8_t> bytes,
                                     size_t pad_to = 0) {
        std::vector<uint8_t> buf(bytes);
        if (pad_to > buf.size()) {
            buf.resize(pad_to, 0);
        }
        return buf;
    }

    /* Helper: create a buffer with magic at an offset */
    std::vector<uint8_t> MakeBufferAt(size_t offset,
                                       std::initializer_list<uint8_t> bytes,
                                       size_t total_size = 0) {
        size_t needed = offset + bytes.size();
        if (total_size < needed) total_size = needed;
        std::vector<uint8_t> buf(total_size, 0);
        size_t i = offset;
        for (auto b : bytes) {
            buf[i++] = b;
        }
        return buf;
    }

    /* Helper: create a fake ZIP with embedded path */
    std::vector<uint8_t> MakeZipWith(const std::string& internal_path) {
        /* Minimal ZIP local file header */
        std::vector<uint8_t> buf = {0x50, 0x4B, 0x03, 0x04};
        /* Pad with zeros for the rest of the local file header (26 bytes) */
        buf.resize(30, 0);
        /* Set filename length at offset 26 (little-endian) */
        uint16_t name_len = static_cast<uint16_t>(internal_path.size());
        buf[26] = static_cast<uint8_t>(name_len & 0xFF);
        buf[27] = static_cast<uint8_t>((name_len >> 8) & 0xFF);
        /* Append filename */
        for (char c : internal_path) {
            buf.push_back(static_cast<uint8_t>(c));
        }
        /* Pad to ensure enough data for compound format scanning */
        buf.resize(std::max(buf.size(), static_cast<size_t>(256)), 0);
        return buf;
    }

    /* Helper: create a RIFF buffer with a fourcc at offset 8 */
    std::vector<uint8_t> MakeRiff(const char* fourcc) {
        std::vector<uint8_t> buf = {
            0x52, 0x49, 0x46, 0x46,  /* "RIFF" */
            0x00, 0x00, 0x00, 0x00,  /* file size (dummy) */
        };
        for (int i = 0; i < 4; ++i) {
            buf.push_back(static_cast<uint8_t>(fourcc[i]));
        }
        buf.resize(64, 0);
        return buf;
    }
};

/* ================================================================== */
/*  Signature count                                                     */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, HasAtLeast50Signatures) {
    EXPECT_GE(detector_.SignatureCount(), 50u);
}

/* ================================================================== */
/*  Document formats                                                    */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectPDF) {
    auto buf = MakeBuffer({0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "PDF");
    EXPECT_EQ(result.category, FileCategory::Document);
    EXPECT_GE(result.confidence, 90);
}

TEST_F(FileTypeDetectorTest, DetectRTF) {
    auto buf = MakeBuffer({0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "RTF");
    EXPECT_EQ(result.category, FileCategory::Document);
}

TEST_F(FileTypeDetectorTest, DetectOLE2) {
    auto buf = MakeBuffer({0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 64);
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "OLE2 Compound");
    EXPECT_EQ(result.category, FileCategory::Document);
}

/* ================================================================== */
/*  ZIP-based Office formats (compound detection)                       */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectDOCX) {
    auto buf = MakeZipWith("word/document.xml");
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "DOCX");
    EXPECT_EQ(result.category, FileCategory::Document);
    EXPECT_GE(result.confidence, 90);
}

TEST_F(FileTypeDetectorTest, DetectXLSX) {
    auto buf = MakeZipWith("xl/workbook.xml");
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "XLSX");
    EXPECT_EQ(result.category, FileCategory::Spreadsheet);
}

TEST_F(FileTypeDetectorTest, DetectPPTX) {
    auto buf = MakeZipWith("ppt/presentation.xml");
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "PPTX");
    EXPECT_EQ(result.category, FileCategory::Presentation);
}

/* ================================================================== */
/*  Images                                                              */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectJPEG) {
    auto buf = MakeBuffer({0xFF, 0xD8, 0xFF, 0xE0});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "JPEG");
    EXPECT_EQ(result.category, FileCategory::Image);
}

TEST_F(FileTypeDetectorTest, DetectPNG) {
    auto buf = MakeBuffer({0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "PNG");
    EXPECT_EQ(result.category, FileCategory::Image);
}

TEST_F(FileTypeDetectorTest, DetectGIF89a) {
    auto buf = MakeBuffer({0x47, 0x49, 0x46, 0x38, 0x39, 0x61});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "GIF89a");
    EXPECT_EQ(result.category, FileCategory::Image);
}

TEST_F(FileTypeDetectorTest, DetectBMP) {
    auto buf = MakeBuffer({0x42, 0x4D, 0x00, 0x00, 0x00, 0x00}, 64);
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "BMP");
    EXPECT_EQ(result.category, FileCategory::Image);
}

TEST_F(FileTypeDetectorTest, DetectTIFF_LE) {
    auto buf = MakeBuffer({0x49, 0x49, 0x2A, 0x00});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "TIFF");
    EXPECT_EQ(result.category, FileCategory::Image);
}

TEST_F(FileTypeDetectorTest, DetectTIFF_BE) {
    auto buf = MakeBuffer({0x4D, 0x4D, 0x00, 0x2A});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "TIFF");
    EXPECT_EQ(result.category, FileCategory::Image);
}

TEST_F(FileTypeDetectorTest, DetectWebP) {
    auto buf = MakeRiff("WEBP");
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "WebP");
    EXPECT_EQ(result.category, FileCategory::Image);
}

TEST_F(FileTypeDetectorTest, DetectICO) {
    auto buf = MakeBuffer({0x00, 0x00, 0x01, 0x00, 0x01, 0x00}, 64);
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "ICO");
    EXPECT_EQ(result.category, FileCategory::Image);
}

TEST_F(FileTypeDetectorTest, DetectPSD) {
    auto buf = MakeBuffer({0x38, 0x42, 0x50, 0x53});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "PSD");
    EXPECT_EQ(result.category, FileCategory::Image);
}

/* ================================================================== */
/*  Audio                                                               */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectMP3_ID3) {
    auto buf = MakeBuffer({0x49, 0x44, 0x33, 0x04});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "MP3");
    EXPECT_EQ(result.category, FileCategory::Audio);
}

TEST_F(FileTypeDetectorTest, DetectWAV) {
    auto buf = MakeRiff("WAVE");
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "WAV");
    EXPECT_EQ(result.category, FileCategory::Audio);
}

TEST_F(FileTypeDetectorTest, DetectFLAC) {
    auto buf = MakeBuffer({0x66, 0x4C, 0x61, 0x43});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "FLAC");
    EXPECT_EQ(result.category, FileCategory::Audio);
}

TEST_F(FileTypeDetectorTest, DetectOGG) {
    auto buf = MakeBuffer({0x4F, 0x67, 0x67, 0x53});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "OGG");
    EXPECT_EQ(result.category, FileCategory::Audio);
}

/* ================================================================== */
/*  Video                                                               */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectAVI) {
    auto buf = MakeRiff("AVI ");
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "AVI");
    EXPECT_EQ(result.category, FileCategory::Video);
}

TEST_F(FileTypeDetectorTest, DetectMP4) {
    auto buf = MakeBufferAt(4, {0x66, 0x74, 0x79, 0x70}, 64);
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "MP4");
    EXPECT_EQ(result.category, FileCategory::Video);
}

TEST_F(FileTypeDetectorTest, DetectMKV) {
    auto buf = MakeBuffer({0x1A, 0x45, 0xDF, 0xA3}, 64);
    /* No "webm" in header, so should default to MKV */
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "MKV");
    EXPECT_EQ(result.category, FileCategory::Video);
}

TEST_F(FileTypeDetectorTest, DetectFLV) {
    auto buf = MakeBuffer({0x46, 0x4C, 0x56, 0x01});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "FLV");
    EXPECT_EQ(result.category, FileCategory::Video);
}

/* ================================================================== */
/*  Archives                                                            */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectZIP) {
    /* Plain ZIP without Office internals */
    auto buf = MakeBuffer({0x50, 0x4B, 0x03, 0x04, 0x00, 0x00}, 64);
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "ZIP");
    EXPECT_EQ(result.category, FileCategory::Archive);
}

TEST_F(FileTypeDetectorTest, DetectRAR5) {
    auto buf = MakeBuffer({0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "RAR5");
    EXPECT_EQ(result.category, FileCategory::Archive);
}

TEST_F(FileTypeDetectorTest, Detect7Zip) {
    auto buf = MakeBuffer({0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "7-Zip");
    EXPECT_EQ(result.category, FileCategory::Archive);
}

TEST_F(FileTypeDetectorTest, DetectGZIP) {
    auto buf = MakeBuffer({0x1F, 0x8B, 0x08});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "GZIP");
    EXPECT_EQ(result.category, FileCategory::Archive);
}

TEST_F(FileTypeDetectorTest, DetectBZ2) {
    auto buf = MakeBuffer({0x42, 0x5A, 0x68, 0x39});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "BZ2");
    EXPECT_EQ(result.category, FileCategory::Archive);
}

TEST_F(FileTypeDetectorTest, DetectXZ) {
    auto buf = MakeBuffer({0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "XZ");
    EXPECT_EQ(result.category, FileCategory::Archive);
}

TEST_F(FileTypeDetectorTest, DetectZSTD) {
    auto buf = MakeBuffer({0x28, 0xB5, 0x2F, 0xFD});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "ZSTD");
    EXPECT_EQ(result.category, FileCategory::Archive);
}

/* ================================================================== */
/*  Executables                                                         */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectPE) {
    auto buf = MakeBuffer({0x4D, 0x5A, 0x90, 0x00}, 64);
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "PE Executable");
    EXPECT_EQ(result.category, FileCategory::Executable);
}

TEST_F(FileTypeDetectorTest, DetectELF) {
    auto buf = MakeBuffer({0x7F, 0x45, 0x4C, 0x46, 0x02});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "ELF");
    EXPECT_EQ(result.category, FileCategory::Executable);
}

TEST_F(FileTypeDetectorTest, DetectMachO64) {
    auto buf = MakeBuffer({0xFE, 0xED, 0xFA, 0xCF});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "Mach-O 64");
    EXPECT_EQ(result.category, FileCategory::Executable);
}

/* ================================================================== */
/*  Database                                                            */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectSQLite) {
    /* "SQLite format 3\0" */
    auto buf = MakeBuffer({0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66,
                            0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "SQLite");
    EXPECT_EQ(result.category, FileCategory::Database);
}

/* ================================================================== */
/*  Scripts                                                             */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectShebang) {
    std::string script = "#!/usr/bin/env python3\nprint('hello')";
    auto result = detector_.DetectFromContent(script.data(), script.size());
    EXPECT_EQ(result.type_name, "Script (Shebang)");
    EXPECT_EQ(result.category, FileCategory::Script);
}

/* ================================================================== */
/*  Fonts                                                               */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectOTF) {
    auto buf = MakeBuffer({0x4F, 0x54, 0x54, 0x4F});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "OpenType Font");
    EXPECT_EQ(result.category, FileCategory::Font);
}

TEST_F(FileTypeDetectorTest, DetectWOFF2) {
    auto buf = MakeBuffer({0x77, 0x4F, 0x46, 0x32});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "WOFF2");
    EXPECT_EQ(result.category, FileCategory::Font);
}

/* ================================================================== */
/*  CAD                                                                 */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DetectDWG) {
    auto buf = MakeBuffer({0x41, 0x43, 0x31, 0x30, 0x31, 0x38});
    auto result = detector_.DetectFromContent(buf.data(), buf.size());
    EXPECT_EQ(result.type_name, "DWG");
    EXPECT_EQ(result.category, FileCategory::CAD);
}

/* ================================================================== */
/*  Acceptance: renamed file detection                                  */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, DocxRenamedToTxt_DetectedAsOffice) {
    /* .docx renamed to .txt — content wins */
    auto buf = MakeZipWith("word/document.xml");
    auto result = detector_.Detect(buf.data(), buf.size(), "report.txt");
    EXPECT_EQ(result.type_name, "DOCX");
    EXPECT_EQ(result.category, FileCategory::Document);
}

TEST_F(FileTypeDetectorTest, ExeRenamedToJpg_DetectedAsPE) {
    /* .exe renamed to .jpg — content wins */
    auto buf = MakeBuffer({0x4D, 0x5A, 0x90, 0x00}, 64);
    auto result = detector_.Detect(buf.data(), buf.size(), "photo.jpg");
    EXPECT_EQ(result.type_name, "PE Executable");
    EXPECT_EQ(result.category, FileCategory::Executable);
}

TEST_F(FileTypeDetectorTest, PdfRenamedToZip_DetectedAsPDF) {
    auto buf = MakeBuffer({0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34});
    auto result = detector_.Detect(buf.data(), buf.size(), "archive.zip");
    EXPECT_EQ(result.type_name, "PDF");
    EXPECT_EQ(result.category, FileCategory::Document);
}

/* ================================================================== */
/*  Name-based detection                                                */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, NameBased_Python) {
    auto result = detector_.DetectFromName("script.py");
    EXPECT_EQ(result.type_name, "Python");
    EXPECT_EQ(result.category, FileCategory::Script);
}

TEST_F(FileTypeDetectorTest, NameBased_PowerShell) {
    auto result = detector_.DetectFromName("setup.ps1");
    EXPECT_EQ(result.type_name, "PowerShell");
    EXPECT_EQ(result.category, FileCategory::Script);
}

TEST_F(FileTypeDetectorTest, NameBased_CaseInsensitive) {
    auto result = detector_.DetectFromName("DOCUMENT.PDF");
    EXPECT_EQ(result.type_name, "PDF");
}

TEST_F(FileTypeDetectorTest, NameBased_UnknownExtension) {
    auto result = detector_.DetectFromName("file.xyz");
    EXPECT_EQ(result.category, FileCategory::Unknown);
}

/* ================================================================== */
/*  Combined detection                                                  */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, CombinedBoostsConfidence) {
    /* PDF content + .pdf name = boosted confidence */
    auto buf = MakeBuffer({0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34});
    auto result = detector_.Detect(buf.data(), buf.size(), "report.pdf");
    EXPECT_EQ(result.type_name, "PDF");
    EXPECT_EQ(result.confidence, 100);
}

TEST_F(FileTypeDetectorTest, CombinedFallsBackToName) {
    /* Unknown content + known name */
    std::vector<uint8_t> buf(64, 0x42);  /* Random bytes */
    auto result = detector_.Detect(buf.data(), buf.size(), "script.ps1");
    EXPECT_EQ(result.type_name, "PowerShell");
    EXPECT_EQ(result.category, FileCategory::Script);
}

/* ================================================================== */
/*  Edge cases                                                          */
/* ================================================================== */

TEST_F(FileTypeDetectorTest, NullBuffer) {
    auto result = detector_.DetectFromContent(static_cast<const uint8_t*>(nullptr), 0);
    EXPECT_EQ(result.category, FileCategory::Unknown);
}

TEST_F(FileTypeDetectorTest, EmptyBuffer) {
    std::vector<uint8_t> empty;
    auto result = detector_.DetectFromContent(empty.data(), 0);
    EXPECT_EQ(result.category, FileCategory::Unknown);
}

TEST_F(FileTypeDetectorTest, TinyBuffer) {
    /* 1 byte — not enough for most signatures */
    uint8_t b = 0xFF;
    auto result = detector_.DetectFromContent(&b, 1);
    /* Might match nothing or a short sig, either way shouldn't crash */
    EXPECT_GE(result.confidence, 0);
}

TEST_F(FileTypeDetectorTest, EmptyFilename) {
    auto result = detector_.DetectFromName("");
    EXPECT_EQ(result.category, FileCategory::Unknown);
}
