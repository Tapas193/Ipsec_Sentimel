"""Capture upload validation and secure storage."""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import CaptureValidationError, StorageError, UnsupportedFormatError
from app.models import Capture
from app.services import next_sequence_id

ALLOWED_EXTENSIONS = {".pcap", ".cap", ".pcapng"}
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


@dataclass
class ValidatedFile:
    original_filename: str
    sha256: str
    capture_format: str
    size: int


def validate_upload_file(filename: str, content: bytes, settings: Settings) -> ValidatedFile:
    """Validate filename, size and magic bytes; compute the SHA-256 digest."""
    if not filename or filename in (".", ".."):
        raise CaptureValidationError("A file must be selected for upload.")
    if "/" in filename or "\\" in filename:
        raise CaptureValidationError("Filename must not contain path separators.")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise UnsupportedFormatError(
            "Unsupported file type.",
            details={"allowed": sorted(ALLOWED_EXTENSIONS)},
        )
    if not content:
        raise CaptureValidationError("The uploaded file is empty.")

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(content) > max_bytes:
        raise CaptureValidationError(
            f"File exceeds the maximum upload size of {settings.MAX_UPLOAD_SIZE_MB} MB.",
            details={"max_bytes": max_bytes, "actual_bytes": len(content)},
        )

    expected_format_by_magic = detect_capture_format_from_bytes(content)
    if expected_format_by_magic is None:
        raise UnsupportedFormatError(
            "File content is not a recognized PCAP or PCAPNG capture.",
        )

    sha256 = hashlib.sha256(content).hexdigest()
    return ValidatedFile(
        original_filename=filename,
        sha256=sha256,
        capture_format=expected_format_by_magic,
        size=len(content),
    )


def detect_capture_format_from_bytes(content: bytes) -> str | None:
    if len(content) < 4:
        return None
    header = content[:4]
    if header in _PCAP_MAGICS:
        return "pcapng" if header == b"\x0a\x0d\x0d\x0a" else "pcap"
    return None


def store_capture_file(
    db: Session, content: bytes, validated: ValidatedFile, settings: Settings | None = None
) -> Capture:
    """Persist the validated capture on disk and as a database record."""
    settings = settings or get_settings()
    upload_dir = os.path.abspath(settings.UPLOAD_DIR)
    os.makedirs(upload_dir, exist_ok=True)

    capture_ref = next_sequence_id(db, Capture, Capture.capture_reference, "CAP", 6)
    extension = ".pcapng" if validated.capture_format == "pcapng" else ".pcap"
    stored_filename = f"{capture_ref}{extension}"
    storage_path = os.path.join(upload_dir, stored_filename)

    # Transactional write: write to a temp file then atomically move into place.
    tmp_path = f"{storage_path}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "wb") as fh:
            fh.write(content)
        shutil.move(tmp_path, storage_path)
    except OSError as exc:
        try:
            os.remove(tmp_path)
        except OSError:  # pragma: no cover - defensive
            pass
        raise StorageError(f"Could not store the uploaded capture: {exc}") from exc

    capture = Capture(
        capture_reference=capture_ref,
        capture_id=capture_ref,
        filename=stored_filename,
        original_filename=validated.original_filename,
        stored_filename=stored_filename,
        file_size=validated.size,
        sha256=validated.sha256,
        capture_format=validated.capture_format,
        status="valid",
        storage_path=storage_path,
        uploaded_at=datetime.now(UTC),
    )
    db.add(capture)
    db.commit()
    db.refresh(capture)
    return capture


def delete_capture_file(db: Session, capture: Capture) -> None:
    """Remove the on-disk capture and its database record."""
    storage_path = capture.storage_path
    db.delete(capture)
    db.commit()
    if storage_path and os.path.isfile(storage_path):
        try:
            os.remove(storage_path)
        except OSError:  # pragma: no cover - best effort cleanup
            pass


def capture_matches_query(capture: Capture, q: str) -> bool:
    q_lower = q.lower()
    return (
        q_lower in (capture.capture_id or "").lower()
        or q_lower in capture.original_filename.lower()
        or capture.sha256.startswith(q_lower)
    )


def get_capture_by_key(db: Session, capture_key: str) -> Capture | None:
    """Look a capture up by its human id (CAP-000001) or raw uuid."""
    if capture_key.startswith("CAP-"):
        return db.scalar(select(Capture).where(Capture.capture_id == capture_key))
    return db.scalar(select(Capture).where(Capture.id == capture_key))
