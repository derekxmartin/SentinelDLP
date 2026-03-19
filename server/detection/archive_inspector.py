"""Archive inspector — recursive extraction with safety controls.

Extracts files from archives (ZIP, TAR, GZIP, 7z, RAR) and feeds them
through FileInspector for content analysis. Implements safety controls
to prevent zip bombs and resource exhaustion:

- Max recursion depth (default 3)
- Max total extracted size (default 100MB)
- Max file count (default 500)
- Compression ratio check (default 1000:1 = zip bomb)
"""

from __future__ import annotations

import gzip
import io
import logging
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import py7zr

from server.detection.file_inspector import FileInspector
from server.detection.models import ComponentType, ParsedMessage

logger = logging.getLogger(__name__)


class ArchiveSafetyError(Exception):
    """Raised when archive extraction violates safety limits."""

    pass


class ZipBombError(ArchiveSafetyError):
    """Raised when compression ratio exceeds safe threshold."""

    pass


class MaxDepthError(ArchiveSafetyError):
    """Raised when archive nesting exceeds max depth."""

    pass


class MaxSizeError(ArchiveSafetyError):
    """Raised when total extracted size exceeds limit."""

    pass


class MaxFilesError(ArchiveSafetyError):
    """Raised when total file count exceeds limit."""

    pass


@dataclass
class ArchiveLimits:
    """Safety limits for archive extraction.

    Attributes:
        max_depth: Maximum nesting depth (e.g., ZIP inside TAR.GZ = depth 2).
        max_total_size: Maximum total bytes extracted across all files.
        max_files: Maximum number of files to extract.
        max_ratio: Maximum compression ratio (uncompressed/compressed).
            Ratios above this indicate a zip bomb.
    """

    max_depth: int = 3
    max_total_size: int = 100 * 1024 * 1024  # 100MB
    max_files: int = 500
    max_ratio: float = 1000.0  # 1000:1


@dataclass
class _ExtractionState:
    """Mutable state tracking across recursive extraction."""

    total_bytes: int = 0
    total_files: int = 0
    errors: list[str] = field(default_factory=list)

    def check_size(self, size: int, limits: ArchiveLimits) -> None:
        if self.total_bytes + size > limits.max_total_size:
            raise MaxSizeError(
                f"Total extracted size would exceed {limits.max_total_size} bytes"
            )

    def check_files(self, limits: ArchiveLimits) -> None:
        if self.total_files >= limits.max_files:
            raise MaxFilesError(
                f"Total file count would exceed {limits.max_files}"
            )

    def add(self, size: int) -> None:
        self.total_bytes += size
        self.total_files += 1


def _check_ratio(
    compressed_size: int,
    uncompressed_size: int,
    limits: ArchiveLimits,
) -> None:
    """Check if compression ratio indicates a zip bomb."""
    if compressed_size > 0:
        ratio = uncompressed_size / compressed_size
        if ratio > limits.max_ratio:
            raise ZipBombError(
                f"Compression ratio {ratio:.0f}:1 exceeds "
                f"max {limits.max_ratio:.0f}:1 — possible zip bomb"
            )


def _is_archive(filename: str, content: bytes) -> str | None:
    """Detect archive type from content magic bytes and filename.

    Returns archive type string or None.
    """
    # Check magic bytes first
    if content[:4] == b"PK\x03\x04":
        return "zip"
    if content[:6] in (b"\x37\x7a\xbc\xaf\x27\x1c",):
        return "7z"
    if content[:7] == b"Rar!\x1a\x07\x00" or content[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar"
    if content[:2] == b"\x1f\x8b":
        return "gzip"
    if content[:5] == b"\x42\x5a\x68":  # BZh
        return "bzip2"

    # TAR detection (magic at offset 257)
    if len(content) > 262 and content[257:262] == b"ustar":
        return "tar"

    # Extension fallback
    ext = PurePosixPath(filename).suffix.lower()
    if ext == ".zip":
        return "zip"
    if ext == ".7z":
        return "7z"
    if ext == ".rar":
        return "rar"
    if ext in (".gz", ".gzip"):
        return "gzip"
    if ext in (".tar",):
        return "tar"
    if ext in (".tgz",) or filename.lower().endswith(".tar.gz"):
        return "tar.gz"
    if ext in (".bz2",):
        return "bzip2"
    if filename.lower().endswith(".tar.bz2"):
        return "tar.bz2"

    return None


class ArchiveInspector:
    """Recursively extracts and inspects files within archives.

    Integrates with FileInspector to extract text content from files
    found inside archives. Supports nested archives up to max_depth.

    Example:
        >>> inspector = ArchiveInspector()
        >>> message = inspector.inspect(zip_bytes, "data.zip")
        >>> # message.components contains text from all extracted files
    """

    def __init__(
        self,
        limits: ArchiveLimits | None = None,
        file_inspector: FileInspector | None = None,
    ) -> None:
        self.limits = limits or ArchiveLimits()
        self.file_inspector = file_inspector or FileInspector()

    def inspect(
        self,
        content: bytes,
        filename: str = "",
        metadata: dict | None = None,
    ) -> ParsedMessage:
        """Extract and inspect all files in an archive.

        Args:
            content: Raw archive bytes.
            filename: Archive filename.
            metadata: Optional metadata for the message.

        Returns:
            ParsedMessage with components from all extracted files.

        Raises:
            ArchiveSafetyError: If safety limits are violated.
        """
        msg = ParsedMessage(metadata=metadata or {})
        state = _ExtractionState()

        try:
            self._extract_recursive(
                content=content,
                filename=filename,
                msg=msg,
                state=state,
                depth=0,
                path_prefix="",
            )
        except ArchiveSafetyError as exc:
            logger.warning("Archive safety limit hit: %s", exc)
            msg.add_component(
                ComponentType.GENERIC,
                f"[Archive safety limit: {exc}]",
                {
                    "filename": filename,
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
            )

        if state.errors:
            for err in state.errors:
                msg.add_component(
                    ComponentType.GENERIC,
                    f"[Extraction error: {err}]",
                    {"filename": filename, "error": err},
                )

        logger.info(
            "Archive %s: extracted %d files, %d bytes, %d errors",
            filename,
            state.total_files,
            state.total_bytes,
            len(state.errors),
        )

        return msg

    def _extract_recursive(
        self,
        content: bytes,
        filename: str,
        msg: ParsedMessage,
        state: _ExtractionState,
        depth: int,
        path_prefix: str,
    ) -> None:
        """Recursively extract archive contents."""
        if depth > self.limits.max_depth:
            raise MaxDepthError(
                f"Nesting depth {depth} exceeds max {self.limits.max_depth}"
            )

        archive_type = _is_archive(filename, content)
        if archive_type is None:
            # Not an archive — inspect as regular file
            self._inspect_file(content, filename, msg, state, path_prefix)
            return

        # Check overall ratio for the archive
        try:
            if archive_type == "zip":
                self._extract_zip(content, filename, msg, state, depth, path_prefix)
            elif archive_type == "tar":
                self._extract_tar(content, filename, msg, state, depth, path_prefix)
            elif archive_type == "gzip":
                self._extract_gzip(content, filename, msg, state, depth, path_prefix)
            elif archive_type == "tar.gz":
                self._extract_gzip(content, filename, msg, state, depth, path_prefix)
            elif archive_type == "7z":
                self._extract_7z(content, filename, msg, state, depth, path_prefix)
            elif archive_type == "rar":
                self._extract_rar(content, filename, msg, state, depth, path_prefix)
            elif archive_type == "bzip2":
                self._extract_bzip2(content, filename, msg, state, depth, path_prefix)
            else:
                state.errors.append(f"Unsupported archive type: {archive_type}")
        except ArchiveSafetyError:
            raise
        except Exception as exc:
            state.errors.append(f"Failed to extract {filename}: {exc}")
            logger.error("Archive extraction failed for %s: %s", filename, exc)

    def _extract_zip(
        self, content, filename, msg, state, depth, path_prefix
    ) -> None:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                state.check_files(self.limits)
                _check_ratio(info.compress_size, info.file_size, self.limits)
                state.check_size(info.file_size, self.limits)

                data = zf.read(info.filename)
                state.add(len(data))

                entry_path = f"{path_prefix}{filename}/{info.filename}"
                entry_name = PurePosixPath(info.filename).name

                # Recursively check if extracted file is also an archive
                self._extract_recursive(
                    data, entry_name, msg, state, depth + 1, entry_path + "/"
                )

    def _extract_tar(
        self, content, filename, msg, state, depth, path_prefix
    ) -> None:
        with tarfile.open(fileobj=io.BytesIO(content)) as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue

                state.check_files(self.limits)
                state.check_size(member.size, self.limits)

                f = tf.extractfile(member)
                if f is None:
                    continue

                data = f.read()
                state.add(len(data))

                entry_name = PurePosixPath(member.name).name
                entry_path = f"{path_prefix}{filename}/{member.name}"

                self._extract_recursive(
                    data, entry_name, msg, state, depth + 1, entry_path + "/"
                )

    def _extract_gzip(
        self, content, filename, msg, state, depth, path_prefix
    ) -> None:
        decompressed = gzip.decompress(content)
        _check_ratio(len(content), len(decompressed), self.limits)
        state.check_size(len(decompressed), self.limits)
        state.add(len(decompressed))

        # Strip .gz extension for inner filename
        inner_name = filename
        if inner_name.lower().endswith(".gz"):
            inner_name = inner_name[:-3]
        elif inner_name.lower().endswith(".gzip"):
            inner_name = inner_name[:-5]

        entry_path = f"{path_prefix}{filename}/"

        self._extract_recursive(
            decompressed, inner_name, msg, state, depth + 1, entry_path
        )

    def _extract_bzip2(
        self, content, filename, msg, state, depth, path_prefix
    ) -> None:
        import bz2

        decompressed = bz2.decompress(content)
        _check_ratio(len(content), len(decompressed), self.limits)
        state.check_size(len(decompressed), self.limits)
        state.add(len(decompressed))

        inner_name = filename
        if inner_name.lower().endswith(".bz2"):
            inner_name = inner_name[:-4]

        entry_path = f"{path_prefix}{filename}/"

        self._extract_recursive(
            decompressed, inner_name, msg, state, depth + 1, entry_path
        )

    def _extract_7z(
        self, content, filename, msg, state, depth, path_prefix
    ) -> None:
        import tempfile
        import shutil
        from pathlib import Path

        tmpdir = tempfile.mkdtemp(prefix="akesodlp_7z_")
        try:
            with py7zr.SevenZipFile(io.BytesIO(content), mode="r") as zf:
                zf.extractall(path=tmpdir)

            for file_path in Path(tmpdir).rglob("*"):
                if not file_path.is_file():
                    continue

                state.check_files(self.limits)
                data = file_path.read_bytes()
                state.check_size(len(data), self.limits)
                state.add(len(data))

                rel_path = file_path.relative_to(tmpdir).as_posix()
                name = file_path.name
                entry_path = f"{path_prefix}{filename}/{rel_path}"

                self._extract_recursive(
                    data, name, msg, state, depth + 1, entry_path + "/"
                )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _extract_rar(
        self, content, filename, msg, state, depth, path_prefix
    ) -> None:
        import rarfile

        with rarfile.RarFile(io.BytesIO(content)) as rf:
            for info in rf.infolist():
                if info.is_dir():
                    continue

                state.check_files(self.limits)
                _check_ratio(info.compress_size, info.file_size, self.limits)
                state.check_size(info.file_size, self.limits)

                data = rf.read(info.filename)
                state.add(len(data))

                name = PurePosixPath(info.filename).name
                entry_path = f"{path_prefix}{filename}/{info.filename}"

                self._extract_recursive(
                    data, name, msg, state, depth + 1, entry_path + "/"
                )

    def _inspect_file(
        self,
        content: bytes,
        filename: str,
        msg: ParsedMessage,
        state: _ExtractionState,
        path_prefix: str,
    ) -> None:
        """Inspect a regular (non-archive) file via FileInspector."""
        try:
            sub_msg = self.file_inspector.inspect(content, filename)
            for comp in sub_msg.components:
                # Enrich metadata with archive path
                comp.metadata["archive_path"] = path_prefix + filename
                msg.components.append(comp)
        except Exception as exc:
            state.errors.append(f"Failed to inspect {filename}: {exc}")
