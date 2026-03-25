"""File type analyzer using python-magic for binary signature detection.

Detects file types by examining magic bytes (binary signatures) rather
than relying on file extensions, which can be spoofed. Also supports
file size conditions and filename pattern matching.

Covers 50+ file types across categories: documents, executables,
archives, images, media, scripts, and data formats.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from enum import Enum

import magic

from server.detection.analyzers import BaseAnalyzer
from server.detection.models import (
    ComponentType,
    Match,
    MessageComponent,
    ParsedMessage,
)

logger = logging.getLogger(__name__)


class FileCategory(str, Enum):
    """High-level file type categories."""

    DOCUMENT = "document"
    EXECUTABLE = "executable"
    ARCHIVE = "archive"
    IMAGE = "image"
    MEDIA = "media"
    SCRIPT = "script"
    DATA = "data"
    ENCRYPTED = "encrypted"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# File type database — 50+ types organized by category
# ---------------------------------------------------------------------------

# Maps MIME types and MIME prefixes to (category, human_name)
MIME_TYPE_DB: dict[str, tuple[FileCategory, str]] = {
    # Documents
    "application/pdf": (FileCategory.DOCUMENT, "PDF"),
    "application/msword": (FileCategory.DOCUMENT, "Microsoft Word (DOC)"),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": (
        FileCategory.DOCUMENT,
        "Microsoft Word (DOCX)",
    ),
    "application/vnd.ms-excel": (FileCategory.DOCUMENT, "Microsoft Excel (XLS)"),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": (
        FileCategory.DOCUMENT,
        "Microsoft Excel (XLSX)",
    ),
    "application/vnd.ms-powerpoint": (
        FileCategory.DOCUMENT,
        "Microsoft PowerPoint (PPT)",
    ),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": (
        FileCategory.DOCUMENT,
        "Microsoft PowerPoint (PPTX)",
    ),
    "application/vnd.oasis.opendocument.text": (
        FileCategory.DOCUMENT,
        "OpenDocument Text (ODT)",
    ),
    "application/vnd.oasis.opendocument.spreadsheet": (
        FileCategory.DOCUMENT,
        "OpenDocument Spreadsheet (ODS)",
    ),
    "application/vnd.oasis.opendocument.presentation": (
        FileCategory.DOCUMENT,
        "OpenDocument Presentation (ODP)",
    ),
    "application/rtf": (FileCategory.DOCUMENT, "Rich Text Format (RTF)"),
    "text/plain": (FileCategory.DOCUMENT, "Plain Text"),
    "text/csv": (FileCategory.DOCUMENT, "CSV"),
    "text/html": (FileCategory.DOCUMENT, "HTML"),
    "text/xml": (FileCategory.DOCUMENT, "XML"),
    "application/xml": (FileCategory.DOCUMENT, "XML"),
    "application/json": (FileCategory.DATA, "JSON"),
    "text/markdown": (FileCategory.DOCUMENT, "Markdown"),
    "message/rfc822": (FileCategory.DOCUMENT, "Email (EML)"),
    "application/epub+zip": (FileCategory.DOCUMENT, "EPUB"),
    # Executables
    "application/x-dosexec": (FileCategory.EXECUTABLE, "Windows Executable (EXE/DLL)"),
    "application/x-executable": (FileCategory.EXECUTABLE, "Linux Executable (ELF)"),
    "application/x-mach-binary": (FileCategory.EXECUTABLE, "macOS Executable (Mach-O)"),
    "application/x-sharedlib": (FileCategory.EXECUTABLE, "Shared Library (SO)"),
    "application/vnd.microsoft.portable-executable": (
        FileCategory.EXECUTABLE,
        "Portable Executable (PE)",
    ),
    "application/x-msdownload": (FileCategory.EXECUTABLE, "Windows Executable (EXE)"),
    "application/java-archive": (FileCategory.EXECUTABLE, "Java Archive (JAR)"),
    "application/x-java-applet": (FileCategory.EXECUTABLE, "Java Applet"),
    # Archives
    "application/zip": (FileCategory.ARCHIVE, "ZIP"),
    "application/x-tar": (FileCategory.ARCHIVE, "TAR"),
    "application/gzip": (FileCategory.ARCHIVE, "GZIP"),
    "application/x-gzip": (FileCategory.ARCHIVE, "GZIP"),
    "application/x-bzip2": (FileCategory.ARCHIVE, "BZIP2"),
    "application/x-xz": (FileCategory.ARCHIVE, "XZ"),
    "application/x-7z-compressed": (FileCategory.ARCHIVE, "7-Zip"),
    "application/x-rar-compressed": (FileCategory.ARCHIVE, "RAR"),
    "application/x-rar": (FileCategory.ARCHIVE, "RAR"),
    "application/vnd.rar": (FileCategory.ARCHIVE, "RAR"),
    "application/x-iso9660-image": (FileCategory.ARCHIVE, "ISO Disk Image"),
    # Images
    "image/jpeg": (FileCategory.IMAGE, "JPEG Image"),
    "image/png": (FileCategory.IMAGE, "PNG Image"),
    "image/gif": (FileCategory.IMAGE, "GIF Image"),
    "image/bmp": (FileCategory.IMAGE, "BMP Image"),
    "image/tiff": (FileCategory.IMAGE, "TIFF Image"),
    "image/webp": (FileCategory.IMAGE, "WebP Image"),
    "image/svg+xml": (FileCategory.IMAGE, "SVG Image"),
    "image/x-icon": (FileCategory.IMAGE, "ICO Image"),
    # Media
    "audio/mpeg": (FileCategory.MEDIA, "MP3 Audio"),
    "audio/wav": (FileCategory.MEDIA, "WAV Audio"),
    "audio/x-wav": (FileCategory.MEDIA, "WAV Audio"),
    "audio/ogg": (FileCategory.MEDIA, "OGG Audio"),
    "audio/flac": (FileCategory.MEDIA, "FLAC Audio"),
    "video/mp4": (FileCategory.MEDIA, "MP4 Video"),
    "video/x-msvideo": (FileCategory.MEDIA, "AVI Video"),
    "video/x-matroska": (FileCategory.MEDIA, "MKV Video"),
    "video/quicktime": (FileCategory.MEDIA, "QuickTime Video"),
    "video/webm": (FileCategory.MEDIA, "WebM Video"),
    # Scripts
    "text/x-python": (FileCategory.SCRIPT, "Python Script"),
    "text/x-shellscript": (FileCategory.SCRIPT, "Shell Script"),
    "application/javascript": (FileCategory.SCRIPT, "JavaScript"),
    "text/javascript": (FileCategory.SCRIPT, "JavaScript"),
    "text/x-perl": (FileCategory.SCRIPT, "Perl Script"),
    "text/x-ruby": (FileCategory.SCRIPT, "Ruby Script"),
    "text/x-php": (FileCategory.SCRIPT, "PHP Script"),
    "application/x-httpd-php": (FileCategory.SCRIPT, "PHP Script"),
    # Data / Database
    "application/x-sqlite3": (FileCategory.DATA, "SQLite Database"),
    "application/x-sql": (FileCategory.DATA, "SQL"),
    "application/yaml": (FileCategory.DATA, "YAML"),
    "text/yaml": (FileCategory.DATA, "YAML"),
    "application/x-protobuf": (FileCategory.DATA, "Protocol Buffers"),
    # Encrypted / Certificates
    "application/x-x509-ca-cert": (FileCategory.ENCRYPTED, "X.509 Certificate"),
    "application/pgp-encrypted": (FileCategory.ENCRYPTED, "PGP Encrypted"),
    "application/pkcs7-signature": (FileCategory.ENCRYPTED, "PKCS#7 Signature"),
}

# Extension-based fallback for types magic can't detect from content alone
EXTENSION_FALLBACK: dict[str, tuple[FileCategory, str]] = {
    ".docx": (FileCategory.DOCUMENT, "Microsoft Word (DOCX)"),
    ".xlsx": (FileCategory.DOCUMENT, "Microsoft Excel (XLSX)"),
    ".pptx": (FileCategory.DOCUMENT, "Microsoft PowerPoint (PPTX)"),
    ".odt": (FileCategory.DOCUMENT, "OpenDocument Text (ODT)"),
    ".ods": (FileCategory.DOCUMENT, "OpenDocument Spreadsheet (ODS)"),
    ".odp": (FileCategory.DOCUMENT, "OpenDocument Presentation (ODP)"),
    ".py": (FileCategory.SCRIPT, "Python Script"),
    ".js": (FileCategory.SCRIPT, "JavaScript"),
    ".ts": (FileCategory.SCRIPT, "TypeScript"),
    ".rb": (FileCategory.SCRIPT, "Ruby Script"),
    ".php": (FileCategory.SCRIPT, "PHP Script"),
    ".sh": (FileCategory.SCRIPT, "Shell Script"),
    ".bat": (FileCategory.SCRIPT, "Batch Script"),
    ".ps1": (FileCategory.SCRIPT, "PowerShell Script"),
    ".sql": (FileCategory.DATA, "SQL"),
    ".yaml": (FileCategory.DATA, "YAML"),
    ".yml": (FileCategory.DATA, "YAML"),
    ".json": (FileCategory.DATA, "JSON"),
    ".csv": (FileCategory.DOCUMENT, "CSV"),
    ".md": (FileCategory.DOCUMENT, "Markdown"),
    ".eml": (FileCategory.DOCUMENT, "Email (EML)"),
}


@dataclass
class FileTypeRule:
    """A rule that matches files based on type, size, or name pattern.

    At least one condition must be set. Multiple conditions are AND'd.

    Attributes:
        name: Rule name for match reporting.
        blocked_categories: File categories to match (e.g., EXECUTABLE).
        blocked_mime_types: Specific MIME types to match.
        blocked_extensions: File extensions to match (e.g., ".exe").
        name_patterns: Filename glob patterns (e.g., "*.xlsx", "report_*").
        min_size: Minimum file size in bytes to trigger.
        max_size: Maximum file size in bytes to trigger (0 = no limit).
        description: Human-readable description.
        confidence: Confidence score for matches.
    """

    name: str
    blocked_categories: list[FileCategory] = field(default_factory=list)
    blocked_mime_types: list[str] = field(default_factory=list)
    blocked_extensions: list[str] = field(default_factory=list)
    name_patterns: list[str] = field(default_factory=list)
    min_size: int = 0
    max_size: int = 0
    description: str = ""
    confidence: float = 1.0


@dataclass
class FileInfo:
    """Detected file type information."""

    mime_type: str
    category: FileCategory
    type_name: str
    filename: str = ""
    extension: str = ""
    size: int = 0


def detect_file_type(
    content: bytes,
    filename: str = "",
) -> FileInfo:
    """Detect file type from content bytes and optional filename.

    Uses python-magic for binary signature detection, with extension-based
    fallback for ambiguous types (e.g., Office Open XML detected as ZIP).

    Args:
        content: File content bytes (at least first 2048 bytes recommended).
        filename: Original filename for extension-based hints.

    Returns:
        FileInfo with detected type information.
    """
    # Detect MIME type from content
    mime_type = magic.from_buffer(content, mime=True)

    # Extract extension
    ext = ""
    if filename:
        dot_idx = filename.rfind(".")
        if dot_idx >= 0:
            ext = filename[dot_idx:].lower()

    # Look up in MIME database
    if mime_type in MIME_TYPE_DB:
        category, type_name = MIME_TYPE_DB[mime_type]
    elif mime_type == "application/zip" and ext in EXTENSION_FALLBACK:
        # Office Open XML files are ZIP-based — use extension to differentiate
        category, type_name = EXTENSION_FALLBACK[ext]
    elif ext in EXTENSION_FALLBACK:
        category, type_name = EXTENSION_FALLBACK[ext]
    else:
        category = FileCategory.UNKNOWN
        type_name = mime_type

    return FileInfo(
        mime_type=mime_type,
        category=category,
        type_name=type_name,
        filename=filename,
        extension=ext,
        size=len(content),
    )


class FileTypeAnalyzer(BaseAnalyzer):
    """Analyzer that detects files by binary signature, size, and name.

    Uses python-magic for content-based file type detection rather than
    relying on extensions (which can be spoofed). Supports rules based on:
    - File category (e.g., block all executables)
    - Specific MIME types
    - File extensions
    - Filename patterns (glob)
    - File size thresholds

    Attachment components must include 'content_bytes' or 'filename'
    and optionally 'size' in their metadata.

    Example:
        >>> rules = [
        ...     FileTypeRule(
        ...         name="Block Executables",
        ...         blocked_categories=[FileCategory.EXECUTABLE],
        ...     ),
        ...     FileTypeRule(
        ...         name="Large Files",
        ...         min_size=10 * 1024 * 1024,  # 10MB
        ...     ),
        ... ]
        >>> analyzer = FileTypeAnalyzer(name="ft", rules=rules)
    """

    def __init__(
        self,
        name: str,
        rules: list[FileTypeRule],
        target_components: list[ComponentType] | None = None,
    ) -> None:
        super().__init__(name=name, target_components=target_components)
        self._rules = rules

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def analyze(self, message: ParsedMessage) -> list[Match]:
        """Analyze attachments for file type violations.

        Components should have metadata with:
        - 'content_bytes' (bytes): Raw file content for magic detection
        - 'filename' (str): Original filename
        - 'size' (int): File size in bytes (optional, derived from content_bytes)

        Args:
            message: The parsed message to analyze.

        Returns:
            List of Match objects for file type rule violations.
        """
        matches: list[Match] = []
        components = self.get_target_components(message)

        for component in components:
            file_info = self._detect_component(component)
            if file_info is None:
                continue

            for rule in self._rules:
                if self._rule_matches(rule, file_info, component):
                    matches.append(
                        Match(
                            analyzer_name=self.name,
                            rule_name=rule.name,
                            component=component,
                            matched_text=file_info.filename
                            or f"[{file_info.type_name}]",
                            start_offset=0,
                            end_offset=0,
                            confidence=rule.confidence,
                            metadata={
                                "mime_type": file_info.mime_type,
                                "category": file_info.category.value,
                                "type_name": file_info.type_name,
                                "filename": file_info.filename,
                                "extension": file_info.extension,
                                "size": file_info.size,
                                "rule": rule.name,
                                "description": rule.description,
                            },
                        )
                    )

        return matches

    def _detect_component(self, component: MessageComponent) -> FileInfo | None:
        """Extract file info from a component's metadata."""
        meta = component.metadata
        content_bytes = meta.get("content_bytes")
        filename = meta.get("filename", "")
        size = meta.get("size", 0)

        if content_bytes is not None:
            info = detect_file_type(content_bytes, filename)
            if size:
                info.size = size
            return info

        # If no content bytes but we have filename, use extension fallback
        if filename:
            ext = ""
            dot_idx = filename.rfind(".")
            if dot_idx >= 0:
                ext = filename[dot_idx:].lower()

            if ext in EXTENSION_FALLBACK:
                cat, tname = EXTENSION_FALLBACK[ext]
            else:
                cat, tname = FileCategory.UNKNOWN, f"Unknown ({ext})"

            return FileInfo(
                mime_type="application/octet-stream",
                category=cat,
                type_name=tname,
                filename=filename,
                extension=ext,
                size=size,
            )

        return None

    def _rule_matches(
        self,
        rule: FileTypeRule,
        info: FileInfo,
        component: MessageComponent,
    ) -> bool:
        """Check if a file type rule matches the detected file info.

        Rules with multiple conditions use AND logic — all specified
        conditions must match for the rule to trigger.
        """
        checks: list[bool] = []

        if rule.blocked_categories:
            checks.append(info.category in rule.blocked_categories)

        if rule.blocked_mime_types:
            checks.append(info.mime_type in rule.blocked_mime_types)

        if rule.blocked_extensions:
            checks.append(
                info.extension.lower() in [e.lower() for e in rule.blocked_extensions]
            )

        if rule.name_patterns:
            filename = info.filename or ""
            checks.append(
                any(
                    fnmatch.fnmatch(filename.lower(), pat.lower())
                    for pat in rule.name_patterns
                )
            )

        if rule.min_size > 0:
            checks.append(info.size >= rule.min_size)

        if rule.max_size > 0:
            checks.append(info.size <= rule.max_size)

        # Must have at least one condition and all must match
        return len(checks) > 0 and all(checks)
