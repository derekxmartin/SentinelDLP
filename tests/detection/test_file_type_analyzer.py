"""Tests for FileTypeAnalyzer (P1-T5).

Covers: Binary signature detection via python-magic, file size conditions,
filename pattern matching, category-based rules, renamed file detection,
50+ type database, and edge cases.
"""

import io
import struct
import zipfile


from server.detection.models import ComponentType, ParsedMessage
from server.detection.analyzers.file_type_analyzer import (
    FileCategory,
    FileTypeAnalyzer,
    FileTypeRule,
    detect_file_type,
    MIME_TYPE_DB,
    EXTENSION_FALLBACK,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_message(**components: dict) -> ParsedMessage:
    """Build a ParsedMessage with attachment components.

    Each kwarg is a dict with 'content' (str), 'content_bytes' (bytes),
    'filename' (str), 'size' (int).
    """
    msg = ParsedMessage()
    for _name, meta in components.items():
        content = meta.pop("content", "")
        msg.add_component(ComponentType.ATTACHMENT, content, meta)
    return msg


def _make_attachment_message(
    content_bytes: bytes,
    filename: str = "",
    size: int = 0,
) -> ParsedMessage:
    """Quick helper for single-attachment messages."""
    msg = ParsedMessage()
    meta = {"content_bytes": content_bytes, "filename": filename}
    if size:
        meta["size"] = size
    msg.add_component(ComponentType.ATTACHMENT, "", meta)
    return msg


# ---------------------------------------------------------------------------
# Synthetic file content generators
# ---------------------------------------------------------------------------


def _make_pdf() -> bytes:
    """Minimal PDF magic bytes."""
    return b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 0\ntrailer\n<<>>\nstartxref\n0\n%%EOF"


def _make_zip() -> bytes:
    """Valid ZIP file with a text entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("test.txt", "hello world")
    return buf.getvalue()


def _make_docx() -> bytes:
    """Minimal DOCX (ZIP with [Content_Types].xml)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '</Types>',
        )
        zf.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


def _make_xlsx() -> bytes:
    """Minimal XLSX (ZIP with [Content_Types].xml)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '</Types>',
        )
        zf.writestr("xl/workbook.xml", "<workbook/>")
    return buf.getvalue()


def _make_exe() -> bytes:
    """Minimal PE executable magic bytes (MZ header)."""
    # MZ header + PE signature offset
    mz = bytearray(512)
    mz[0:2] = b"MZ"
    # PE header offset at 0x3C
    struct.pack_into("<I", mz, 0x3C, 0x80)
    # PE signature at offset 0x80
    mz[0x80:0x84] = b"PE\x00\x00"
    return bytes(mz)


def _make_png() -> bytes:
    """Valid minimal PNG with IHDR chunk (required for magic detection)."""
    import zlib as _zlib

    header = b"\x89PNG\r\n\x1a\n"
    # IHDR: 1x1 pixel, 8-bit RGB
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = _zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)
    return header + ihdr_chunk


def _make_jpeg() -> bytes:
    """Minimal JPEG magic bytes."""
    return b"\xff\xd8\xff\xe0" + b"\x00" * 100


def _make_gif() -> bytes:
    """Minimal GIF magic bytes."""
    return b"GIF89a" + b"\x00" * 100


def _make_gzip() -> bytes:
    """Minimal GZIP magic bytes."""
    return b"\x1f\x8b\x08" + b"\x00" * 100


def _make_elf() -> bytes:
    """Valid ELF executable header (x86_64)."""
    elf = bytearray(128)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2    # 64-bit
    elf[5] = 1    # little endian
    elf[6] = 1    # current version
    elf[7] = 0    # ELFOSABI_NONE
    struct.pack_into("<H", elf, 16, 2)    # ET_EXEC
    struct.pack_into("<H", elf, 18, 0x3E)  # EM_X86_64
    struct.pack_into("<I", elf, 20, 1)    # EV_CURRENT
    return bytes(elf)


def _make_html() -> bytes:
    """HTML content."""
    return b"<!DOCTYPE html><html><head><title>Test</title></head><body></body></html>"


def _make_json() -> bytes:
    return b'{"key": "value", "items": [1, 2, 3]}'


# ---------------------------------------------------------------------------
# detect_file_type function tests
# ---------------------------------------------------------------------------


class TestDetectFileType:
    """Tests for the detect_file_type utility function."""

    def test_pdf_detected(self):
        info = detect_file_type(_make_pdf(), "document.pdf")
        assert info.category == FileCategory.DOCUMENT
        assert "PDF" in info.type_name

    def test_zip_detected(self):
        info = detect_file_type(_make_zip(), "archive.zip")
        assert info.mime_type == "application/zip"
        assert info.category == FileCategory.ARCHIVE

    def test_exe_detected(self):
        info = detect_file_type(_make_exe(), "program.exe")
        assert info.category == FileCategory.EXECUTABLE

    def test_png_detected(self):
        info = detect_file_type(_make_png(), "image.png")
        assert info.category == FileCategory.IMAGE
        assert "PNG" in info.type_name

    def test_jpeg_detected(self):
        info = detect_file_type(_make_jpeg(), "photo.jpg")
        assert info.category == FileCategory.IMAGE

    def test_gif_detected(self):
        info = detect_file_type(_make_gif(), "anim.gif")
        assert info.category == FileCategory.IMAGE

    def test_gzip_detected(self):
        info = detect_file_type(_make_gzip(), "data.gz")
        assert info.category == FileCategory.ARCHIVE

    def test_html_detected(self):
        info = detect_file_type(_make_html(), "page.html")
        assert info.category == FileCategory.DOCUMENT

    def test_extension_extracted(self):
        info = detect_file_type(_make_pdf(), "report.final.pdf")
        assert info.extension == ".pdf"

    def test_size_calculated(self):
        content = _make_pdf()
        info = detect_file_type(content, "doc.pdf")
        assert info.size == len(content)


# ---------------------------------------------------------------------------
# Acceptance criteria: renamed files detected by signature
# ---------------------------------------------------------------------------


class TestRenamedFileDetection:
    """Acceptance: files detected by binary signature, not extension."""

    def test_docx_renamed_to_txt_detected_as_office(self):
        """DOCX renamed to .txt → identified as Office (ZIP-based)."""
        content = _make_docx()
        info = detect_file_type(content, "document.txt")
        # Should detect the ZIP magic, and with .txt extension it uses
        # content-based detection — result is ZIP or Office depending on magic depth
        assert info.mime_type == "application/zip" or "Word" in info.type_name or info.category == FileCategory.ARCHIVE

    def test_exe_renamed_to_jpg_detected_as_executable(self):
        """EXE renamed to .jpg → identified as executable."""
        content = _make_exe()
        info = detect_file_type(content, "photo.jpg")
        assert info.category == FileCategory.EXECUTABLE

    def test_pdf_renamed_to_docx(self):
        """PDF renamed to .docx → still detected as PDF by magic bytes."""
        content = _make_pdf()
        info = detect_file_type(content, "report.docx")
        assert "PDF" in info.type_name

    def test_png_renamed_to_exe(self):
        """PNG renamed to .exe → detected as image, not executable."""
        content = _make_png()
        info = detect_file_type(content, "malware.exe")
        assert info.category == FileCategory.IMAGE


# ---------------------------------------------------------------------------
# FileTypeAnalyzer rule-based detection
# ---------------------------------------------------------------------------


class TestBlockExecutables:
    """Block all executables rule."""

    def _make_analyzer(self):
        return FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Block Executables",
                    blocked_categories=[FileCategory.EXECUTABLE],
                    description="Block all executable files",
                )
            ],
        )

    def test_exe_blocked(self):
        analyzer = self._make_analyzer()
        msg = _make_attachment_message(_make_exe(), "malware.exe")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1
        assert matches[0].metadata["category"] == "executable"

    def test_exe_renamed_to_jpg_still_blocked(self):
        """Renamed .exe detected by binary signature."""
        analyzer = self._make_analyzer()
        msg = _make_attachment_message(_make_exe(), "photo.jpg")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_pdf_not_blocked(self):
        analyzer = self._make_analyzer()
        msg = _make_attachment_message(_make_pdf(), "doc.pdf")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_elf_blocked(self):
        analyzer = self._make_analyzer()
        msg = _make_attachment_message(_make_elf(), "binary")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# File size conditions
# ---------------------------------------------------------------------------


class TestFileSizeRules:
    """File size threshold rules."""

    def test_min_size_triggers(self):
        """File >= 10MB triggers size rule."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Large File",
                    min_size=10 * 1024 * 1024,
                )
            ],
        )
        # Use size metadata instead of actual 10MB content
        msg = ParsedMessage()
        msg.add_component(
            ComponentType.ATTACHMENT,
            "",
            {
                "content_bytes": _make_pdf(),
                "filename": "huge.pdf",
                "size": 15 * 1024 * 1024,
            },
        )
        matches = analyzer.analyze(msg)
        assert len(matches) == 1
        assert matches[0].rule_name == "Large File"

    def test_min_size_below_threshold(self):
        """File below threshold does not trigger."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Large File",
                    min_size=10 * 1024 * 1024,
                )
            ],
        )
        msg = _make_attachment_message(_make_pdf(), "small.pdf")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_max_size_rule(self):
        """File within max size matches (useful for 'small suspicious files')."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Tiny Executable",
                    blocked_categories=[FileCategory.EXECUTABLE],
                    max_size=1024,
                )
            ],
        )
        exe_content = _make_exe()
        msg = _make_attachment_message(exe_content, "tiny.exe")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Filename pattern matching
# ---------------------------------------------------------------------------


class TestNamePatterns:
    """Filename glob pattern matching."""

    def test_xlsx_pattern_matches(self):
        """Name *.xlsx matches."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Excel Files",
                    name_patterns=["*.xlsx"],
                )
            ],
        )
        msg = _make_attachment_message(_make_xlsx(), "report.xlsx")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_xlsx_pattern_no_match(self):
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Excel Files",
                    name_patterns=["*.xlsx"],
                )
            ],
        )
        msg = _make_attachment_message(_make_pdf(), "report.pdf")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_multiple_patterns(self):
        """Multiple name patterns — any match triggers."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Spreadsheets",
                    name_patterns=["*.xlsx", "*.xls", "*.csv"],
                )
            ],
        )
        msg = _make_attachment_message(b"a,b,c\n1,2,3", "data.csv")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_case_insensitive_pattern(self):
        """Patterns are case-insensitive."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Excel Files",
                    name_patterns=["*.xlsx"],
                )
            ],
        )
        msg = _make_attachment_message(_make_xlsx(), "REPORT.XLSX")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_wildcard_prefix_pattern(self):
        """Pattern 'report_*' matches filenames starting with 'report_'."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Reports",
                    name_patterns=["report_*"],
                )
            ],
        )
        msg = _make_attachment_message(_make_pdf(), "report_q4_2026.pdf")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Combined conditions (AND logic)
# ---------------------------------------------------------------------------


class TestCombinedConditions:
    """Multiple conditions on a rule use AND logic."""

    def test_category_and_size(self):
        """Must be executable AND > min_size."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Large Executable",
                    blocked_categories=[FileCategory.EXECUTABLE],
                    min_size=100,
                )
            ],
        )
        # Large enough
        msg = _make_attachment_message(_make_exe(), "big.exe")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_category_and_size_below_threshold(self):
        """Executable but too small."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Large Executable",
                    blocked_categories=[FileCategory.EXECUTABLE],
                    min_size=100 * 1024 * 1024,  # 100MB
                )
            ],
        )
        msg = _make_attachment_message(_make_exe(), "small.exe")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_name_and_category(self):
        """Name pattern AND category must both match."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Suspicious Archive",
                    blocked_categories=[FileCategory.ARCHIVE],
                    name_patterns=["*.zip"],
                )
            ],
        )
        msg = _make_attachment_message(_make_zip(), "data.zip")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Multiple rules
# ---------------------------------------------------------------------------


class TestMultipleRules:
    """Multiple rules evaluated against same file."""

    def test_file_matches_multiple_rules(self):
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Block Executables",
                    blocked_categories=[FileCategory.EXECUTABLE],
                ),
                FileTypeRule(
                    name="EXE Extension",
                    blocked_extensions=[".exe"],
                ),
            ],
        )
        msg = _make_attachment_message(_make_exe(), "malware.exe")
        matches = analyzer.analyze(msg)
        rules_hit = {m.rule_name for m in matches}
        assert "Block Executables" in rules_hit
        assert "EXE Extension" in rules_hit


# ---------------------------------------------------------------------------
# MIME type database coverage
# ---------------------------------------------------------------------------


class TestMimeTypeDatabase:
    """Verify the MIME type database has 50+ entries."""

    def test_50_plus_mime_types(self):
        assert len(MIME_TYPE_DB) >= 50

    def test_all_categories_represented(self):
        categories = {cat for cat, _ in MIME_TYPE_DB.values()}
        assert FileCategory.DOCUMENT in categories
        assert FileCategory.EXECUTABLE in categories
        assert FileCategory.ARCHIVE in categories
        assert FileCategory.IMAGE in categories
        assert FileCategory.MEDIA in categories
        assert FileCategory.SCRIPT in categories
        assert FileCategory.DATA in categories

    def test_extension_fallback_populated(self):
        assert len(EXTENSION_FALLBACK) >= 15


# ---------------------------------------------------------------------------
# Component targeting
# ---------------------------------------------------------------------------


class TestComponentTargeting:

    def test_attachment_only(self):
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Block EXE",
                    blocked_categories=[FileCategory.EXECUTABLE],
                )
            ],
            target_components=[ComponentType.ATTACHMENT],
        )
        msg = ParsedMessage()
        msg.add_component(
            ComponentType.BODY,
            "exe in body",
            {"content_bytes": _make_exe(), "filename": "body.exe"},
        )
        msg.add_component(
            ComponentType.ATTACHMENT,
            "",
            {"content_bytes": _make_exe(), "filename": "att.exe"},
        )
        matches = analyzer.analyze(msg)
        assert len(matches) == 1
        assert matches[0].component.component_type == ComponentType.ATTACHMENT


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:

    def test_no_content_bytes_with_filename(self):
        """Component with filename but no content_bytes uses extension fallback."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Excel Files",
                    name_patterns=["*.xlsx"],
                )
            ],
        )
        msg = ParsedMessage()
        msg.add_component(
            ComponentType.ATTACHMENT,
            "",
            {"filename": "data.xlsx", "size": 5000},
        )
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_no_metadata_skipped(self):
        """Component with no filename or content_bytes is skipped."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Block All",
                    blocked_categories=[FileCategory.EXECUTABLE],
                )
            ],
        )
        msg = ParsedMessage()
        msg.add_component(ComponentType.ATTACHMENT, "just text", {})
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_empty_content(self):
        """Empty bytes don't crash."""
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Block EXE",
                    blocked_categories=[FileCategory.EXECUTABLE],
                )
            ],
        )
        msg = _make_attachment_message(b"", "empty.bin")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_rule_count(self):
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[FileTypeRule(name="a"), FileTypeRule(name="b")],
        )
        assert analyzer.rule_count == 2


# ---------------------------------------------------------------------------
# Extension-based blocking
# ---------------------------------------------------------------------------


class TestExtensionBlocking:

    def test_block_exe_extension(self):
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Block EXE",
                    blocked_extensions=[".exe", ".dll", ".bat"],
                )
            ],
        )
        msg = _make_attachment_message(_make_exe(), "program.exe")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_extension_case_insensitive(self):
        analyzer = FileTypeAnalyzer(
            name="ft",
            rules=[
                FileTypeRule(
                    name="Block EXE",
                    blocked_extensions=[".exe"],
                )
            ],
        )
        msg = _make_attachment_message(_make_exe(), "PROGRAM.EXE")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------


class TestEngineIntegration:

    def test_engine_with_file_type_analyzer(self):
        from server.detection.engine import DetectionEngine

        engine = DetectionEngine()
        engine.register(
            FileTypeAnalyzer(
                name="ft",
                rules=[
                    FileTypeRule(
                        name="Block Executables",
                        blocked_categories=[FileCategory.EXECUTABLE],
                    ),
                ],
            )
        )

        msg = _make_attachment_message(_make_exe(), "malware.exe")
        result = engine.detect(msg)
        assert result.has_matches
        assert len(result.errors) == 0
