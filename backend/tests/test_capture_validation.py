"""Tests for capture upload validation and secure storage."""

from __future__ import annotations

import hashlib

import pytest

from app.core.config import Settings
from app.core.exceptions import CaptureValidationError, UnsupportedFormatError
from app.services.capture_store import validate_upload_file

VALID_MAGIC = b"\xd4\xc3\xb2\xa1"


def _settings(tmp_path: object) -> Settings:
    return Settings(UPLOAD_DIR=str(tmp_path), MAX_UPLOAD_SIZE_MB=1)


class TestValidateUpload:
    def test_rejects_empty_filename(self, tmp_path: object) -> None:
        with pytest.raises(CaptureValidationError):
            validate_upload_file("", b"\x00" * 4, _settings(tmp_path))

    def test_rejects_path_traversal_in_filename(self, tmp_path: object) -> None:
        with pytest.raises(CaptureValidationError):
            validate_upload_file("../evil.pcap", b"\x00" * 4, _settings(tmp_path))

    def test_rejects_unsupported_extension(self, tmp_path: object) -> None:
        with pytest.raises(UnsupportedFormatError):
            validate_upload_file("capture.exe", b"" * 4, _settings(tmp_path))

    def test_rejects_empty_content(self, tmp_path: object) -> None:
        with pytest.raises(CaptureValidationError):
            validate_upload_file("cap.pcap", b"", _settings(tmp_path))

    def test_rejects_bogus_magic(self, tmp_path: object) -> None:
        with pytest.raises(UnsupportedFormatError):
            validate_upload_file("cap.pcap", b"NOTAPCAP", _settings(tmp_path))

    def test_rejects_oversize_file(self, tmp_path: object) -> None:
        settings = _settings(tmp_path)
        content = VALID_MAGIC + b"\x00" * (settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024)
        with pytest.raises(CaptureValidationError):
            validate_upload_file("cap.pcap", content, settings)

    def test_accepts_valid_pcap(self, tmp_path: object) -> None:
        content = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20
        validated = validate_upload_file("sample.pcap", content, _settings(tmp_path))
        assert validated.capture_format == "pcap"
        assert validated.original_filename == "sample.pcap"
        assert validated.sha256 == hashlib.sha256(content).hexdigest()

    def test_accepts_pcapng_magic(self, tmp_path: object) -> None:
        content = b"\x0a\x0d\x0d\x0a" + b"\x00" * 8
        validated = validate_upload_file("sample.pcapng", content, _settings(tmp_path))
        assert validated.capture_format == "pcapng"
