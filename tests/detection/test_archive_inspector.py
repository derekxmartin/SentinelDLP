"""Tests for ArchiveInspector (P1-T7).

Covers: ZIP, TAR, GZIP, 7z extraction, nested archives, zip bomb detection,
max depth/size/files limits, integration with FileInspector and DetectionEngine.
"""

import gzip
import io
import tarfile
import zipfile

import py7zr
import pytest

from server.detection.models import ComponentType, ParsedMessage
from server.detection.archive_inspector import (
    ArchiveInspector,
    ArchiveLimits,
    ArchiveSafetyError,
    MaxDepthError,
    MaxFilesError,
    MaxSizeError,
    ZipBombError,
)


# ---------------------------------------------------------------------------
# Helpers — synthetic archive generators
# ---------------------------------------------------------------------------


def _make_zip(files: dict[str, bytes]) -> bytes:
    """Create a ZIP with the given filename→content mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _make_tar(files: dict[str, bytes]) -> bytes:
    """Create a TAR with the given filename→content mapping."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_tar_gz(files: dict[str, bytes]) -> bytes:
    """Create a TAR.GZ archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_gzip(content: bytes, inner_name: str = "data") -> bytes:
    """Create a GZIP compressed file."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(content)
    return buf.getvalue()


def _make_7z(files: dict[str, bytes]) -> bytes:
    """Create a 7z archive."""
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, mode="w") as zf:
        for name, content in files.items():
            zf.writestr(content, name)
    return buf.getvalue()


def _make_docx_simple(text: str) -> bytes:
    """Create a minimal DOCX with text."""
    from docx import Document

    doc = Document()
    doc.add_paragraph(text)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Basic extraction tests
# ---------------------------------------------------------------------------


class TestZIPExtraction:
    """Basic ZIP archive extraction."""

    def test_zip_with_text_file(self):
        inspector = ArchiveInspector()
        zip_bytes = _make_zip({"data.txt": b"SSN: 123-45-6789"})
        msg = inspector.inspect(zip_bytes, "archive.zip")

        body_comps = [c for c in msg.components if c.component_type == ComponentType.BODY]
        assert len(body_comps) >= 1
        all_text = " ".join(c.content for c in body_comps)
        assert "123-45-6789" in all_text

    def test_zip_with_multiple_files(self):
        inspector = ArchiveInspector()
        zip_bytes = _make_zip({
            "file1.txt": b"Credit card: 4532015112830366",
            "file2.txt": b"SSN: 123-45-6789",
            "file3.txt": b"Email: user@example.com",
        })
        msg = inspector.inspect(zip_bytes, "data.zip")

        body_comps = [c for c in msg.components if c.component_type == ComponentType.BODY]
        all_text = " ".join(c.content for c in body_comps)
        assert "4532015112830366" in all_text
        assert "123-45-6789" in all_text
        assert "user@example.com" in all_text

    def test_keyword_in_docx_inside_zip(self):
        """Acceptance: keyword in DOCX inside ZIP → detected."""
        inspector = ArchiveInspector()
        docx = _make_docx_simple("CONFIDENTIAL: SSN 123-45-6789 salary $150,000")
        zip_bytes = _make_zip({"employees.docx": docx})
        msg = inspector.inspect(zip_bytes, "data.zip")

        all_text = " ".join(c.content for c in msg.components if c.content)
        assert "CONFIDENTIAL" in all_text
        assert "123-45-6789" in all_text


class TestTARExtraction:
    """TAR archive extraction."""

    def test_tar_with_text_files(self):
        inspector = ArchiveInspector()
        tar_bytes = _make_tar({"secret.txt": b"API key: sk-12345"})
        msg = inspector.inspect(tar_bytes, "data.tar")

        body_comps = [c for c in msg.components if c.component_type == ComponentType.BODY]
        assert len(body_comps) >= 1
        assert "sk-12345" in body_comps[0].content


class TestGZIPExtraction:
    """GZIP extraction."""

    def test_gzip_text(self):
        inspector = ArchiveInspector()
        gz_bytes = _make_gzip(b"Sensitive data: SSN 123-45-6789")
        msg = inspector.inspect(gz_bytes, "data.txt.gz")

        body_comps = [c for c in msg.components if c.component_type == ComponentType.BODY]
        assert len(body_comps) >= 1
        assert "123-45-6789" in body_comps[0].content

    def test_tar_gz(self):
        inspector = ArchiveInspector()
        tar_gz = _make_tar_gz({
            "file1.txt": b"Secret file one",
            "file2.txt": b"Secret file two",
        })
        msg = inspector.inspect(tar_gz, "archive.tar.gz")

        body_comps = [c for c in msg.components if c.component_type == ComponentType.BODY]
        all_text = " ".join(c.content for c in body_comps)
        assert "Secret file one" in all_text
        assert "Secret file two" in all_text


class Test7zExtraction:
    """7z archive extraction."""

    def test_7z_with_text(self):
        inspector = ArchiveInspector()
        sz_bytes = _make_7z({"secret.txt": b"Password: hunter2"})
        msg = inspector.inspect(sz_bytes, "data.7z")

        body_comps = [c for c in msg.components if c.component_type == ComponentType.BODY]
        assert len(body_comps) >= 1
        assert "hunter2" in body_comps[0].content


# ---------------------------------------------------------------------------
# Nested archives (acceptance test)
# ---------------------------------------------------------------------------


class TestNestedArchives:
    """Recursive archive extraction."""

    def test_zip_inside_tar_gz_depth_2(self):
        """Acceptance: nested ZIP in TAR.GZ (depth 2) → extracted and scanned."""
        inspector = ArchiveInspector()

        # Inner ZIP containing a text file
        inner_zip = _make_zip({"secret.txt": b"TOP SECRET: 123-45-6789"})
        # Outer TAR.GZ containing the ZIP
        outer = _make_tar_gz({"inner.zip": inner_zip})

        msg = inspector.inspect(outer, "nested.tar.gz")

        all_text = " ".join(c.content for c in msg.components if c.content)
        assert "TOP SECRET" in all_text
        assert "123-45-6789" in all_text

    def test_zip_in_zip(self):
        """ZIP inside ZIP → both layers extracted."""
        inspector = ArchiveInspector()

        inner = _make_zip({"data.txt": b"Nested secret data"})
        outer = _make_zip({"inner.zip": inner})

        msg = inspector.inspect(outer, "outer.zip")

        all_text = " ".join(c.content for c in msg.components if c.content)
        assert "Nested secret data" in all_text

    def test_triple_nested(self):
        """3 levels of nesting (within default max_depth=3)."""
        inspector = ArchiveInspector()

        level3 = _make_zip({"deep.txt": b"Deeply nested secret"})
        level2 = _make_zip({"level3.zip": level3})
        level1 = _make_zip({"level2.zip": level2})

        msg = inspector.inspect(level1, "level1.zip")

        all_text = " ".join(c.content for c in msg.components if c.content)
        assert "Deeply nested secret" in all_text

    def test_archive_path_metadata(self):
        """Extracted files have archive_path metadata."""
        inspector = ArchiveInspector()
        zip_bytes = _make_zip({"data.txt": b"test content"})
        msg = inspector.inspect(zip_bytes, "archive.zip")

        body_comps = [c for c in msg.components if c.component_type == ComponentType.BODY]
        assert any("archive_path" in c.metadata for c in body_comps)


# ---------------------------------------------------------------------------
# Safety: zip bomb detection
# ---------------------------------------------------------------------------


class TestZipBombDetection:
    """Zip bomb and safety limit tests."""

    def test_zip_bomb_ratio_rejected(self):
        """Acceptance: Zip bomb (1000:1 ratio) rejected."""
        inspector = ArchiveInspector(limits=ArchiveLimits(max_ratio=1000.0))

        # Create a file that compresses extremely well (all zeros)
        # 10MB of zeros compresses to just a few KB
        bomb_content = b"\x00" * (10 * 1024 * 1024)
        zip_bytes = _make_zip({"bomb.bin": bomb_content})

        # The ratio of this will be well over 1000:1
        msg = inspector.inspect(zip_bytes, "bomb.zip")

        # Should have a safety error component
        error_comps = [
            c for c in msg.components
            if "safety" in c.content.lower() or "bomb" in c.content.lower()
            or c.metadata.get("error") == "ZipBombError"
        ]
        assert len(error_comps) >= 1

    def test_low_ratio_allowed(self):
        """Normal compression ratio is allowed."""
        inspector = ArchiveInspector()
        # Regular text doesn't compress at extreme ratios
        content = b"Hello world! This is normal text content. " * 100
        zip_bytes = _make_zip({"normal.txt": content})

        msg = inspector.inspect(zip_bytes, "normal.zip")

        body_comps = [c for c in msg.components if c.component_type == ComponentType.BODY]
        assert len(body_comps) >= 1
        assert "Hello world" in body_comps[0].content


# ---------------------------------------------------------------------------
# Safety: max depth
# ---------------------------------------------------------------------------


class TestMaxDepth:
    """Max recursion depth enforcement."""

    def test_exceeds_max_depth(self):
        """Nesting beyond max_depth is caught."""
        inspector = ArchiveInspector(limits=ArchiveLimits(max_depth=1))

        inner = _make_zip({"deep.txt": b"too deep"})
        outer = _make_zip({"inner.zip": inner})

        msg = inspector.inspect(outer, "outer.zip")

        error_comps = [
            c for c in msg.components
            if c.metadata.get("error") == "MaxDepthError"
        ]
        assert len(error_comps) >= 1

    def test_within_max_depth(self):
        """Nesting within max_depth succeeds."""
        inspector = ArchiveInspector(limits=ArchiveLimits(max_depth=3))

        inner = _make_zip({"data.txt": b"within limits"})
        outer = _make_zip({"inner.zip": inner})

        msg = inspector.inspect(outer, "outer.zip")

        all_text = " ".join(c.content for c in msg.components if c.content)
        assert "within limits" in all_text


# ---------------------------------------------------------------------------
# Safety: max size
# ---------------------------------------------------------------------------


class TestMaxSize:
    """Max total extracted size enforcement."""

    def test_exceeds_max_size(self):
        inspector = ArchiveInspector(
            limits=ArchiveLimits(max_total_size=1000)
        )
        # 2KB file exceeds 1000 byte limit
        zip_bytes = _make_zip({"big.txt": b"x" * 2000})

        msg = inspector.inspect(zip_bytes, "big.zip")

        error_comps = [
            c for c in msg.components
            if c.metadata.get("error") == "MaxSizeError"
        ]
        assert len(error_comps) >= 1


# ---------------------------------------------------------------------------
# Safety: max files
# ---------------------------------------------------------------------------


class TestMaxFiles:
    """Max file count enforcement."""

    def test_exceeds_max_files(self):
        inspector = ArchiveInspector(limits=ArchiveLimits(max_files=3))

        files = {f"file{i}.txt": f"content {i}".encode() for i in range(10)}
        zip_bytes = _make_zip(files)

        msg = inspector.inspect(zip_bytes, "many.zip")

        error_comps = [
            c for c in msg.components
            if c.metadata.get("error") == "MaxFilesError"
        ]
        assert len(error_comps) >= 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:

    def test_empty_zip(self):
        inspector = ArchiveInspector()
        zip_bytes = _make_zip({})
        msg = inspector.inspect(zip_bytes, "empty.zip")
        # No errors, just no content
        error_comps = [c for c in msg.components if "error" in c.metadata]
        assert len(error_comps) == 0

    def test_zip_with_directories(self):
        """Directories in ZIP are skipped."""
        inspector = ArchiveInspector()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("dir/", "")
            zf.writestr("dir/file.txt", "secret data")
        zip_bytes = buf.getvalue()

        msg = inspector.inspect(zip_bytes, "with_dirs.zip")
        body_comps = [c for c in msg.components if c.component_type == ComponentType.BODY]
        assert len(body_comps) >= 1
        assert "secret data" in body_comps[0].content

    def test_corrupt_file_in_zip_graceful(self):
        """Corrupt file inside ZIP doesn't crash the whole extraction."""
        inspector = ArchiveInspector()
        zip_bytes = _make_zip({
            "good.txt": b"Good content here",
            "bad.pdf": b"%PDF-corrupt-not-real",
        })
        msg = inspector.inspect(zip_bytes, "mixed.zip")
        # Good file should still be extracted
        all_text = " ".join(c.content for c in msg.components if c.content)
        assert "Good content" in all_text

    def test_metadata_passed_through(self):
        inspector = ArchiveInspector()
        zip_bytes = _make_zip({"data.txt": b"test"})
        msg = inspector.inspect(
            zip_bytes, "data.zip", metadata={"channel": "email"}
        )
        assert msg.metadata["channel"] == "email"


# ---------------------------------------------------------------------------
# Integration: ArchiveInspector → DetectionEngine
# ---------------------------------------------------------------------------


class TestEngineIntegration:

    def test_archive_to_detection_pipeline(self):
        """Full pipeline: archive → extract → inspect → detect."""
        from server.detection.engine import DetectionEngine
        from server.detection.analyzers.regex_analyzer import RegexAnalyzer, RegexPattern

        engine = DetectionEngine()
        engine.register(
            RegexAnalyzer(
                name="ssn",
                patterns=[
                    RegexPattern(name="US SSN", pattern=r"\b\d{3}-\d{2}-\d{4}\b")
                ],
            )
        )

        # DOCX with SSN inside a ZIP
        docx = _make_docx_simple("Employee SSN: 123-45-6789")
        zip_bytes = _make_zip({"employees.docx": docx})

        inspector = ArchiveInspector()
        msg = inspector.inspect(zip_bytes, "data.zip")
        result = engine.detect(msg)

        assert result.has_matches
        ssn_matches = [m for m in result.matches if m.rule_name == "US SSN"]
        assert len(ssn_matches) >= 1
        assert "123-45-6789" in ssn_matches[0].matched_text

    def test_nested_archive_to_detection(self):
        """Nested archive: TAR.GZ containing ZIP with text → detection works."""
        from server.detection.engine import DetectionEngine
        from server.detection.analyzers.keyword_analyzer import (
            KeywordAnalyzer,
            KeywordDictionaryConfig,
        )

        engine = DetectionEngine()
        engine.register(
            KeywordAnalyzer(
                name="kw",
                dictionaries=[
                    KeywordDictionaryConfig(
                        name="secrets",
                        keywords=["top secret", "classified"],
                    )
                ],
            )
        )

        inner_zip = _make_zip({"memo.txt": b"This document is TOP SECRET and classified"})
        outer = _make_tar_gz({"inner.zip": inner_zip})

        inspector = ArchiveInspector()
        msg = inspector.inspect(outer, "nested.tar.gz")
        result = engine.detect(msg)

        assert result.has_matches
        keywords = {m.metadata["keyword"] for m in result.matches}
        assert "top secret" in keywords
        assert "classified" in keywords
