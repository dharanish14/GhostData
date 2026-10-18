"""
GhostData - File Validation and Security Verification
Ensures files meet format specifications, size restrictions, and authentic file signatures.
"""

import os
import uuid
from typing import Tuple, Optional
from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError

# Default upload configuration
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit
ALLOWED_MIME_TYPES = {
    "image/jpeg": ".jpg",
    "application/pdf": ".pdf"
}

# Magic byte signatures (file headers)
MAGIC_SIGNATURES = {
    "jpeg": [
        b"\xff\xd8\xff\xe0",  # Standard JPEG / JFIF
        b"\xff\xd8\xff\xe1",  # Standard JPEG / EXIF
        b"\xff\xd8\xff\xe2",  # JPEG Canon / Extended
        b"\xff\xd8\xff\xe3",  # JPEG Samsung / Extended
        b"\xff\xd8\xff\xe8",  # JPEG SPIFF
        b"\xff\xd8\xff\xdb",  # Raw JPEG without metadata header
        b"\xff\xd8\xff\xee",  # Adobe JPEG
    ],
    "pdf": [
        b"%PDF-1.",  # Standard PDF signature (e.g., %PDF-1.4, %PDF-1.7)
        b"%PDF-2.",  # Modern PDF 2.0 signature
    ]
}


class FileValidationError(Exception):
    """Custom exception raised when a file fails validation checks."""
    def __init__(self, message: str, code: str = "VALIDATION_FAILED"):
        super().__init__(message)
        self.message = message
        self.code = code


def detect_file_type_by_magic_bytes(header_bytes: bytes) -> Optional[str]:
    """
    Examines the initial bytes of a file to determine the true file type.
    Does not trust client-supplied filename extensions or Content-Type headers.
    """
    if len(header_bytes) < 4:
        return None

    # JPEG starts with FF D8 FF
    if header_bytes.startswith(b"\xff\xd8\xff"):
        return "jpeg"

    # PDF starts with %PDF- (standard allows up to 1024 bytes before %PDF-, but standard headers start immediately)
    if header_bytes.startswith(b"%PDF-") or b"%PDF-" in header_bytes[:1024]:
        return "pdf"

    return None


def validate_file_structure(file_path: str, detected_type: str) -> None:
    """
    Attempts a minimal parse of the file using official parsers (Pillow, pypdf)
    to confirm the internal structure is not corrupt, truncated, or an exploit payload.
    """
    if detected_type == "jpeg":
        try:
            with Image.open(file_path) as img:
                # verify() validates integrity of header and blocks without decoding entire pixel raster
                img.verify()
            # Note: After verify(), Image instance cannot be reused without re-opening.
        except (UnidentifiedImageError, OSError, SyntaxError, ValueError) as exc:
            raise FileValidationError(
                f"The uploaded file has a JPEG signature but its structure is corrupt or invalid: {exc}",
                code="CORRUPT_JPEG"
            )

    elif detected_type == "pdf":
        try:
            reader = PdfReader(file_path, strict=False)
            if reader.is_encrypted:
                # We can note encryption or reject encrypted files that require passwords
                # For privacy analysis, if password is required and not decryptable with empty string, notify user
                try:
                    decrypt_res = reader.decrypt("")
                    # decrypt returns 0 if failed, 1/2 if success
                except Exception:
                    pass
            # Check page count access
            _ = len(reader.pages)
        except (PdfReadError, Exception) as exc:
            raise FileValidationError(
                f"The uploaded file has a PDF signature but cannot be parsed as a valid PDF: {exc}",
                code="CORRUPT_PDF"
            )
    else:
        raise FileValidationError(f"Unsupported file type: {detected_type}", code="UNSUPPORTED_TYPE")


def generate_secure_storage_path(storage_dir: str, detected_type: str) -> Tuple[str, str]:
    """
    Generates a cryptographically random filename using UUIDv4.
    Never uses the client-supplied filename as the filesystem storage path.
    Returns (safe_filename, absolute_file_path).
    """
    os.makedirs(storage_dir, exist_ok=True)
    extension = ".jpg" if detected_type == "jpeg" else ".pdf"
    safe_filename = f"{uuid.uuid4().hex}{extension}"
    full_path = os.path.abspath(os.path.join(storage_dir, safe_filename))
    return safe_filename, full_path


def validate_uploaded_file(
    file_stream,
    original_filename: str,
    storage_dir: str,
    max_size_bytes: int = MAX_FILE_SIZE_BYTES
) -> Tuple[str, str, str, int]:
    """
    Complete end-to-end validator:
    1. Checks file size without reading entire file into memory at once.
    2. Inspects magic bytes from initial stream chunk.
    3. Saves securely to isolated directory with UUID filename.
    4. Runs deep structural parser verification.
    
    Returns:
        (detected_type, safe_filename, full_path, file_size)
    """
    # Read initial chunk for magic byte signature detection
    header = file_stream.read(2048)
    if not header:
        raise FileValidationError("The uploaded file is empty (0 bytes).", code="EMPTY_FILE")

    detected_type = detect_file_type_by_magic_bytes(header)
    if not detected_type:
        raise FileValidationError(
            "Unsupported or unrecognized file type. GhostData currently supports valid JPEG images and PDF documents.",
            code="UNSUPPORTED_TYPE"
        )

    # Generate safe random filename
    safe_filename, full_path = generate_secure_storage_path(storage_dir, detected_type)

    # Write file to storage while enforcing max size limits
    total_size = len(header)
    if total_size > max_size_bytes:
        raise FileValidationError(
            f"File exceeds maximum allowed size of {max_size_bytes // (1024 * 1024)} MB.",
            code="FILE_TOO_LARGE"
        )

    try:
        with open(full_path, "wb") as destination:
            destination.write(header)
            chunk_size = 64 * 1024  # 64 KB chunks
            while True:
                chunk = file_stream.read(chunk_size)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > max_size_bytes:
                    raise FileValidationError(
                        f"File exceeds maximum allowed size of {max_size_bytes // (1024 * 1024)} MB.",
                        code="FILE_TOO_LARGE"
                    )
                destination.write(chunk)
    except FileValidationError:
        # Clean up partial file on size violation
        if os.path.exists(full_path):
            os.remove(full_path)
        raise
    except Exception as exc:
        if os.path.exists(full_path):
            os.remove(full_path)
        raise FileValidationError(f"Failed to securely save uploaded file: {exc}", code="WRITE_ERROR")

    # Verify structural integrity
    try:
        validate_file_structure(full_path, detected_type)
    except FileValidationError:
        if os.path.exists(full_path):
            os.remove(full_path)
        raise

    return detected_type, safe_filename, full_path, total_size
