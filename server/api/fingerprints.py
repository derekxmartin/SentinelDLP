"""Fingerprint management API — upload, list, delete (P6-T2).

Endpoints:
  POST   /api/fingerprints/upload  — Upload a document to fingerprint
  GET    /api/fingerprints         — List all indexed fingerprints
  GET    /api/fingerprints/{id}    — Get a single fingerprint record
  DELETE /api/fingerprints/{id}    — Remove a fingerprint from the index
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from pydantic import BaseModel

from server.api.dependencies import RequirePermission
from server.detection.analyzers.fingerprint_analyzer import (
    FingerprintIndex,
    FingerprintRecord,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/fingerprints", tags=["fingerprints"])

# Shared index instance — loaded once, persists across requests.
_index = FingerprintIndex()


def get_index() -> FingerprintIndex:
    """Dependency to provide the fingerprint index."""
    return _index


# --- Response schemas ---


class FingerprintResponse(BaseModel):
    id: str
    name: str
    description: str
    text_length: int
    shingle_count: int
    shingle_size: int
    content_preview: str

    @classmethod
    def from_record(cls, rec: FingerprintRecord) -> FingerprintResponse:
        return cls(
            id=rec.id,
            name=rec.name,
            description=rec.description,
            text_length=rec.text_length,
            shingle_count=rec.shingle_count,
            shingle_size=rec.shingle_size,
            content_preview=rec.content_preview,
        )


class FingerprintListResponse(BaseModel):
    fingerprints: list[FingerprintResponse]
    total: int


class DeleteResponse(BaseModel):
    deleted: bool
    id: str


# --- Endpoints ---


MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


@router.post("/upload", response_model=FingerprintResponse, status_code=201)
async def upload_fingerprint(
    file: UploadFile = File(...),
    name: str = Form(""),
    description: str = Form(""),
    user=Depends(RequirePermission("system:admin")),
    index: FingerprintIndex = Depends(get_index),
):
    """Upload a document to be fingerprinted.

    Accepts plain text or common document formats. Extracts text content,
    computes simhash fingerprint, and stores in the index.
    """
    content = await file.read()

    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE // (1024 * 1024)} MB.",
        )

    # Decode text content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = content.decode("latin-1")
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not decode file content. Upload a text-based document.",
            )

    # Use filename as name if not provided
    doc_name = name.strip() or (file.filename or "Unnamed Document")

    try:
        record = index.add(text, name=doc_name, description=description.strip())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    logger.info(
        "Document fingerprinted: %r by user %s (id=%s)",
        doc_name,
        user.username,
        record.id,
    )
    return FingerprintResponse.from_record(record)


@router.get("", response_model=FingerprintListResponse)
async def list_fingerprints(
    user=Depends(RequirePermission("system:admin")),
    index: FingerprintIndex = Depends(get_index),
):
    """List all indexed document fingerprints."""
    records = index.list_all()
    return FingerprintListResponse(
        fingerprints=[FingerprintResponse.from_record(r) for r in records],
        total=len(records),
    )


@router.get("/{fingerprint_id}", response_model=FingerprintResponse)
async def get_fingerprint(
    fingerprint_id: str,
    user=Depends(RequirePermission("system:admin")),
    index: FingerprintIndex = Depends(get_index),
):
    """Get a single fingerprint record."""
    record = index.get(fingerprint_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Fingerprint {fingerprint_id} not found.",
        )
    return FingerprintResponse.from_record(record)


@router.delete("/{fingerprint_id}", response_model=DeleteResponse)
async def delete_fingerprint(
    fingerprint_id: str,
    user=Depends(RequirePermission("system:admin")),
    index: FingerprintIndex = Depends(get_index),
):
    """Remove a fingerprint from the index."""
    deleted = index.remove(fingerprint_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Fingerprint {fingerprint_id} not found.",
        )

    logger.info(
        "Fingerprint deleted: %s by user %s",
        fingerprint_id,
        user.username,
    )
    return DeleteResponse(deleted=True, id=fingerprint_id)
