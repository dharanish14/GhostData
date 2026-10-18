"""
GhostData Analyzer Package
Privacy Risk Analyzer and Metadata Sanitizer for JPEG and PDF files.
"""

from .validators import validate_uploaded_file, FileValidationError
from .image_metadata import extract_image_metadata
from .pdf_metadata import extract_pdf_metadata
from .risk_engine import analyze_privacy_risks, RiskFinding, Severity
from .cleaner import clean_file
from .verifier import verify_cleaning

__all__ = [
    "validate_uploaded_file",
    "FileValidationError",
    "extract_image_metadata",
    "extract_pdf_metadata",
    "analyze_privacy_risks",
    "RiskFinding",
    "Severity",
    "clean_file",
    "verify_cleaning",
]
