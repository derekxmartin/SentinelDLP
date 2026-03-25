"""Simhash-based document fingerprint analyzer (P6-T1).

Indexes confidential documents by computing simhash fingerprints from
text shingles (character n-grams). Incoming content is fingerprinted
and compared against the index via Hamming distance to detect partial
content reuse.

Algorithm overview:
  1. Normalize text → lowercase, collapse whitespace.
  2. Generate k-shingles (overlapping character n-grams).
  3. Hash each shingle (FNV-1a 64-bit).
  4. Compute simhash: for each bit position, sum +1 for 1-bits
     and -1 for 0-bits across all shingle hashes; final bit is 1
     if sum > 0, else 0.
  5. Compare fingerprints via Hamming distance → similarity score.

Similarity = 1 - (hamming_distance / 64).  Default threshold: 0.40.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from server.detection.analyzers import BaseAnalyzer
from server.detection.models import (
    ComponentType,
    Match,
    ParsedMessage,
)

logger = logging.getLogger(__name__)

# Number of bits in our simhash
SIMHASH_BITS = 64

# Default shingle size (characters)
DEFAULT_SHINGLE_SIZE = 4

# Default similarity threshold (0.0–1.0)
DEFAULT_SIMILARITY_THRESHOLD = 0.40

# Minimum text length to fingerprint (too short = meaningless hash)
MIN_TEXT_LENGTH = 50

# Storage file for the fingerprint index
DEFAULT_INDEX_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "fingerprint_index.json"
)


def _normalize_text(text: str) -> str:
    """Normalize text for fingerprinting.

    Lowercases, strips non-alphanumeric (except spaces),
    and collapses whitespace to single spaces.
    """
    text = text.lower()
    text = re.sub(r"[^\w\s]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _generate_shingles(text: str, k: int = DEFAULT_SHINGLE_SIZE) -> list[str]:
    """Generate k-character shingles from text."""
    if len(text) < k:
        return [text] if text else []
    return [text[i : i + k] for i in range(len(text) - k + 1)]


def _fnv1a_64(data: bytes) -> int:
    """FNV-1a 64-bit hash."""
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def compute_simhash(text: str, shingle_size: int = DEFAULT_SHINGLE_SIZE) -> int:
    """Compute a 64-bit simhash from text.

    Args:
        text: Raw text to fingerprint.
        shingle_size: Character n-gram size.

    Returns:
        64-bit simhash integer.
    """
    normalized = _normalize_text(text)
    shingles = _generate_shingles(normalized, shingle_size)

    if not shingles:
        return 0

    # Accumulate bit weights
    weights = [0] * SIMHASH_BITS

    for shingle in shingles:
        h = _fnv1a_64(shingle.encode("utf-8"))
        for i in range(SIMHASH_BITS):
            if h & (1 << i):
                weights[i] += 1
            else:
                weights[i] -= 1

    # Build final hash
    fingerprint = 0
    for i in range(SIMHASH_BITS):
        if weights[i] > 0:
            fingerprint |= 1 << i

    return fingerprint


def hamming_distance(a: int, b: int) -> int:
    """Count differing bits between two 64-bit integers."""
    return bin(a ^ b).count("1")


def similarity_score(a: int, b: int) -> float:
    """Compute similarity between two simhashes (0.0–1.0)."""
    return 1.0 - (hamming_distance(a, b) / SIMHASH_BITS)


@dataclass
class FingerprintRecord:
    """A stored document fingerprint."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    simhash: int = 0
    text_length: int = 0
    shingle_count: int = 0
    shingle_size: int = DEFAULT_SHINGLE_SIZE
    content_preview: str = ""  # first 200 chars for display


class FingerprintIndex:
    """Persistent index of document fingerprints.

    Stores fingerprints as JSON. Thread-safe for reads; writes are
    serialized through save().
    """

    def __init__(self, path: Path | None = None):
        self._path = path or DEFAULT_INDEX_PATH
        self._records: dict[str, FingerprintRecord] = {}
        self._load()

    def _load(self) -> None:
        """Load index from disk."""
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                for item in data.get("fingerprints", []):
                    rec = FingerprintRecord(**item)
                    self._records[rec.id] = rec
                logger.info(
                    "Loaded %d fingerprints from %s", len(self._records), self._path
                )
            except (json.JSONDecodeError, TypeError, KeyError) as e:
                logger.warning("Failed to load fingerprint index: %s", e)

    def _save(self) -> None:
        """Persist index to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {"fingerprints": [asdict(r) for r in self._records.values()]}
        self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def add(
        self,
        text: str,
        name: str,
        description: str = "",
        shingle_size: int = DEFAULT_SHINGLE_SIZE,
    ) -> FingerprintRecord:
        """Index a document by computing and storing its simhash.

        Args:
            text: Full document text.
            name: Human-readable document name.
            description: Optional description.
            shingle_size: Character n-gram size.

        Returns:
            The created FingerprintRecord.

        Raises:
            ValueError: If text is too short to fingerprint.
        """
        normalized = _normalize_text(text)
        if len(normalized) < MIN_TEXT_LENGTH:
            raise ValueError(
                f"Text too short to fingerprint ({len(normalized)} chars, "
                f"minimum {MIN_TEXT_LENGTH})"
            )

        shingles = _generate_shingles(normalized, shingle_size)
        fp = compute_simhash(text, shingle_size)

        record = FingerprintRecord(
            name=name,
            description=description,
            simhash=fp,
            text_length=len(normalized),
            shingle_count=len(shingles),
            shingle_size=shingle_size,
            content_preview=text[:200].strip(),
        )

        self._records[record.id] = record
        self._save()
        logger.info("Indexed document %r (id=%s, simhash=%016x)", name, record.id, fp)
        return record

    def remove(self, record_id: str) -> bool:
        """Remove a fingerprint from the index.

        Returns True if the record existed and was removed.
        """
        if record_id in self._records:
            name = self._records[record_id].name
            del self._records[record_id]
            self._save()
            logger.info("Removed fingerprint %r (id=%s)", name, record_id)
            return True
        return False

    def list_all(self) -> list[FingerprintRecord]:
        """Return all fingerprint records."""
        return list(self._records.values())

    def get(self, record_id: str) -> FingerprintRecord | None:
        """Get a fingerprint record by ID."""
        return self._records.get(record_id)

    def search(
        self,
        text: str,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        shingle_size: int = DEFAULT_SHINGLE_SIZE,
    ) -> list[tuple[FingerprintRecord, float]]:
        """Search the index for documents similar to the given text.

        Args:
            text: Text to compare against indexed documents.
            threshold: Minimum similarity score (0.0–1.0).
            shingle_size: Must match the shingle size used during indexing.

        Returns:
            List of (record, similarity) tuples sorted by similarity descending.
        """
        if not self._records:
            return []

        normalized = _normalize_text(text)
        if len(normalized) < MIN_TEXT_LENGTH:
            return []

        query_hash = compute_simhash(text, shingle_size)
        results = []

        for record in self._records.values():
            if record.shingle_size != shingle_size:
                continue
            score = similarity_score(query_hash, record.simhash)
            if score >= threshold:
                results.append((record, score))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    @property
    def count(self) -> int:
        """Number of indexed documents."""
        return len(self._records)


class FingerprintAnalyzer(BaseAnalyzer):
    """Analyzer that detects content matching indexed document fingerprints.

    Computes simhash of incoming message components and compares against
    the fingerprint index. Reports matches above the similarity threshold.
    """

    def __init__(
        self,
        name: str = "fingerprint",
        target_components: list[ComponentType] | None = None,
        index: FingerprintIndex | None = None,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        shingle_size: int = DEFAULT_SHINGLE_SIZE,
    ):
        if target_components is None:
            target_components = [ComponentType.BODY, ComponentType.ATTACHMENT]
        super().__init__(name=name, target_components=target_components)
        self.index = index or FingerprintIndex()
        self.threshold = threshold
        self.shingle_size = shingle_size

    def analyze(self, message: ParsedMessage) -> list[Match]:
        """Scan message components against the fingerprint index."""
        matches: list[Match] = []
        components = self.get_target_components(message)

        for component in components:
            text = component.content
            normalized = _normalize_text(text)

            if len(normalized) < MIN_TEXT_LENGTH:
                continue

            results = self.index.search(
                text,
                threshold=self.threshold,
                shingle_size=self.shingle_size,
            )

            for record, score in results:
                matches.append(
                    Match(
                        analyzer_name=self.name,
                        rule_name=f"fingerprint:{record.name}",
                        component=component,
                        matched_text=text[:100],  # Preview of matched content
                        start_offset=0,
                        end_offset=len(text),
                        confidence=score,
                        metadata={
                            "fingerprint_id": record.id,
                            "document_name": record.name,
                            "similarity_score": round(score, 4),
                            "threshold": self.threshold,
                            "hamming_distance": hamming_distance(
                                compute_simhash(text, self.shingle_size),
                                record.simhash,
                            ),
                        },
                    )
                )

        return matches
