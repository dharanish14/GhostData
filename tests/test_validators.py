"""
Tests for GhostData File Validators and Security Measures
"""

import io
import os
import pytest
from analyzer.validators import (
    validate_uploaded_file,
    detect_file_type_by_magic_bytes,
    validate_file_structure,
    generate_secure_storage_path,
    FileValidationError,
    MAX_FILE_SIZE_BYTES
)


def test_detect_jpeg_magic_bytes():
    assert detect_file_type_by_magic_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF") == "jpeg"
    assert detect_file_type_by_magic_bytes(b"\xff\xd8\xff\xe1\x00\x18Exif") == "jpeg"


def test_detect_pdf_magic_bytes():
    assert detect_file_type_by_magic_bytes(b"%PDF-1.7\r\n") == "pdf"
    assert detect_file_type_by_magic_bytes(b"%PDF-2.0\r\n") == "pdf"


def test_reject_unsupported_magic_bytes():
    assert detect_file_type_by_magic_bytes(b"GIF89a\x00\x00") is None
    assert detect_file_type_by_magic_bytes(b"\x89PNG\r\n\x1a\n") is None
    assert detect_file_type_by_magic_bytes(b"MZ\x90\x00\x03\x00\x00\x00") is None  # EXE
    assert detect_file_type_by_magic_bytes(b"Plain text file") is None


def test_secure_storage_path_never_uses_original_name(tmp_path):
    storage_dir = str(tmp_path)
    safe_name, full_path = generate_secure_storage_path(storage_dir, "jpeg")
    assert safe_name.endswith(".jpg")
    assert "evil_payload" not in safe_name
    assert os.path.isabs(full_path)
    assert os.path.dirname(full_path) == storage_dir


def test_reject_empty_file(tmp_path):
    empty_stream = io.BytesIO(b"")
    with pytest.raises(FileValidationError) as exc_info:
        validate_uploaded_file(empty_stream, "empty.jpg", str(tmp_path))
    assert exc_info.value.code == "EMPTY_FILE"


def test_reject_extension_spoofing(tmp_path):
    # A text file renamed to malicious.jpg
    fake_jpg = io.BytesIO(b"Hello world, I am secretly an exploit text file.")
    with pytest.raises(FileValidationError) as exc_info:
        validate_uploaded_file(fake_jpg, "malicious.jpg", str(tmp_path))
    assert exc_info.value.code == "UNSUPPORTED_TYPE"


def test_reject_oversized_file(tmp_path):
    # Create stream exceeding max limit (test with small 100-byte max limit)
    large_payload = io.BytesIO(b"\xff\xd8\xff\xe0" + (b"A" * 500))
    with pytest.raises(FileValidationError) as exc_info:
        validate_uploaded_file(large_payload, "oversized.jpg", str(tmp_path), max_size_bytes=200)
    assert exc_info.value.code == "FILE_TOO_LARGE"


def test_reject_corrupt_jpeg(tmp_path):
    # Magic bytes of JPEG but truncated/corrupt body
    corrupt_jpeg = io.BytesIO(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01NOT_A_VALID_IMAGE")
    with pytest.raises(FileValidationError) as exc_info:
        validate_uploaded_file(corrupt_jpeg, "corrupt.jpg", str(tmp_path))
    assert exc_info.value.code == "CORRUPT_JPEG"


def test_reject_corrupt_pdf(tmp_path):
    corrupt_pdf = io.BytesIO(b"%PDF-1.4\r\nNOT_A_VALID_PDF_STREAM_TRAILER_MISSING")
    with pytest.raises(FileValidationError) as exc_info:
        validate_uploaded_file(corrupt_pdf, "corrupt.pdf", str(tmp_path))
    assert exc_info.value.code == "CORRUPT_PDF"
