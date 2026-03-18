"""Detection API endpoints (P2-T3).

Endpoints:
  POST /api/detect       — Scan text for sensitive data
  POST /api/detect/file  — Upload file, extract content, scan for sensitive data
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from server.api.dependencies import CurrentUser, RequirePermission
from server.detection.engine import DetectionEngine
from server.detection.analyzers.data_identifier_analyzer import (
    DataIdentifierAnalyzer,
    DataIdentifierConfig,
)
from server.detection.file_inspector import FileInspector
from server.detection.models import (
    ComponentType,
    Match,
    ParsedMessage,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/detect", tags=["detection"])

# Maximum upload size: 50 MB
MAX_UPLOAD_SIZE = 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class TextDetectRequest(BaseModel):
    """Request body for text detection."""

    text: str = Field(min_length=1, max_length=10_000_000)
    subject: str | None = Field(default=None, max_length=10_000)
    sender: str | None = None
    recipients: list[str] | None = None


class MatchResponse(BaseModel):
    """A single detection match."""

    analyzer_name: str
    rule_name: str
    component_type: str
    component_name: str
    matched_text: str
    start_offset: int
    end_offset: int
    confidence: float
    metadata: dict = {}


class DetectionResponse(BaseModel):
    """Response from detection scan."""

    message_id: str
    match_count: int
    matches: list[MatchResponse]
    components_scanned: int
    errors: list[str] = []


# ---------------------------------------------------------------------------
# Built-in analyzer factory
# ---------------------------------------------------------------------------


def _build_default_engine() -> DetectionEngine:
    """Build a detection engine with all built-in data identifiers.

    In a production system, this would load from the database configuration.
    For now, it provides the 10 built-in data identifiers inline.
    """
    engine = DetectionEngine()

    # Credit card numbers (Visa, Mastercard, Amex, Discover)
    cc_config = DataIdentifierConfig(
        name="Credit Card Number",
        patterns=[
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        ],
        validator="luhn",
        confidence=0.95,
    )

    # US Social Security Numbers
    ssn_config = DataIdentifierConfig(
        name="US SSN",
        patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
        validator="ssn_area",
        confidence=0.9,
    )

    # US Phone Numbers
    phone_config = DataIdentifierConfig(
        name="US Phone Number",
        patterns=[
            r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        ],
        validator="phone_format",
        confidence=0.7,
    )

    # Email Addresses
    email_config = DataIdentifierConfig(
        name="Email Address",
        patterns=[
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b",
        ],
        validator="email_domain",
        confidence=0.85,
    )

    # IBAN
    iban_config = DataIdentifierConfig(
        name="IBAN",
        patterns=[
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]){0,16}\b",
        ],
        validator="iban_mod97",
        confidence=0.9,
    )

    # IPv4 Addresses
    ipv4_config = DataIdentifierConfig(
        name="IPv4 Address",
        patterns=[
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        ],
        validator="ipv4_range",
        confidence=0.6,
    )

    # Date of Birth
    dob_config = DataIdentifierConfig(
        name="Date of Birth",
        patterns=[
            r"\b\d{2}/\d{2}/\d{4}\b",
            r"\b\d{4}-\d{2}-\d{2}\b",
            r"\b\d{2}-\d{2}-\d{4}\b",
        ],
        validator="date_calendar",
        confidence=0.5,
    )

    # ABA Routing Number
    aba_config = DataIdentifierConfig(
        name="ABA Routing Number",
        patterns=[
            r"\b\d{9}\b",
        ],
        validator="aba_checksum",
        confidence=0.8,
    )

    analyzer = DataIdentifierAnalyzer(
        name="built_in_data_identifiers",
        identifiers=[
            cc_config, ssn_config, phone_config, email_config,
            iban_config, ipv4_config, dob_config, aba_config,
        ],
    )
    engine.register(analyzer)

    return engine


def _match_to_response(m: Match) -> MatchResponse:
    """Convert internal Match dataclass to API response model."""
    return MatchResponse(
        analyzer_name=m.analyzer_name,
        rule_name=m.rule_name,
        component_type=m.component.component_type.value,
        component_name=m.component.name,
        matched_text=m.matched_text,
        start_offset=m.start_offset,
        end_offset=m.end_offset,
        confidence=m.confidence,
        metadata=m.metadata,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=DetectionResponse)
async def detect_text(
    body: TextDetectRequest,
    user: CurrentUser = Depends(RequirePermission("detection:run")),
):
    """Scan text for sensitive data.

    Builds a ParsedMessage from the provided text (body + optional subject),
    runs all built-in data identifiers, and returns matches with locations.
    """
    message = ParsedMessage(message_id=str(uuid.uuid4()))

    # Add body component
    message.add_component(ComponentType.BODY, body.text)

    # Add subject if provided
    if body.subject:
        message.add_component(ComponentType.SUBJECT, body.subject)

    # Add envelope metadata if provided
    if body.sender or body.recipients:
        envelope_parts = []
        if body.sender:
            envelope_parts.append(f"From: {body.sender}")
        if body.recipients:
            envelope_parts.append(f"To: {', '.join(body.recipients)}")
        message.add_component(
            ComponentType.ENVELOPE,
            "\n".join(envelope_parts),
            metadata={"sender": body.sender, "recipients": body.recipients},
        )

    engine = _build_default_engine()
    result = engine.detect(message)

    return DetectionResponse(
        message_id=result.message_id,
        match_count=result.match_count,
        matches=[_match_to_response(m) for m in result.matches],
        components_scanned=len(message.components),
        errors=result.errors,
    )


@router.post("/file", response_model=DetectionResponse)
async def detect_file(
    file: UploadFile = File(...),
    user: CurrentUser = Depends(RequirePermission("detection:run")),
):
    """Upload a file, extract content, and scan for sensitive data.

    Supports PDF, DOCX, XLSX, PPTX, EML, TXT, HTML, and other formats
    via the FileInspector. Extracted text is then run through all built-in
    data identifiers.
    """
    # Read file
    content = await file.read()

    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE // (1024 * 1024)}MB.",
        )

    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file uploaded.",
        )

    # Extract text content from file
    inspector = FileInspector()
    try:
        message = inspector.inspect(
            content,
            filename=file.filename or "unknown",
        )
    except Exception as exc:
        logger.error("File inspection failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to extract content from file: {exc}",
        )

    if not message.components:
        return DetectionResponse(
            message_id=message.message_id,
            match_count=0,
            matches=[],
            components_scanned=0,
            errors=["No text content could be extracted from the file."],
        )

    # Run detection
    engine = _build_default_engine()
    result = engine.detect(message)

    return DetectionResponse(
        message_id=result.message_id,
        match_count=result.match_count,
        matches=[_match_to_response(m) for m in result.matches],
        components_scanned=len(message.components),
        errors=result.errors,
    )
