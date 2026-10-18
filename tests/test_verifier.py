"""
Tests for GhostData Post-Cleaning Verification Engine
"""

import os
from analyzer.image_metadata import extract_image_metadata
from analyzer.risk_engine import analyze_privacy_risks
from analyzer.cleaner import clean_file
from analyzer.verifier import verify_cleaning, verify_file_validity


def test_verify_file_validity(sample_dir):
    jpg_path = os.path.join(sample_dir, "sample_clean.jpg")
    v_jpg = verify_file_validity(jpg_path, "JPEG")
    assert v_jpg["is_valid"] is True
    assert v_jpg["can_open"] is True

    pdf_path = os.path.join(sample_dir, "sample_clean.pdf")
    v_pdf = verify_file_validity(pdf_path, "PDF")
    assert v_pdf["is_valid"] is True
    assert v_pdf["can_open"] is True


def test_full_cleaning_and_verification_pipeline(sample_dir, tmp_path):
    orig_jpg = os.path.join(sample_dir, "sample_with_gps.jpg")
    orig_meta = extract_image_metadata(orig_jpg)
    orig_risk = analyze_privacy_risks(orig_meta)

    clean_dir = str(tmp_path / "cleaned")
    clean_name, clean_path, details = clean_file(orig_jpg, "JPEG", clean_dir)

    verif = verify_cleaning(
        original_metadata=orig_meta,
        original_risk=orig_risk,
        cleaned_file_path=clean_path,
        file_type="JPEG",
        cleaner_notes=details.get("notes", []),
        unsupported_structures=details.get("unsupported_structures", [])
    )

    assert verif["is_verified_clean"] is True
    assert verif["verification_status"] == "VERIFIED_CLEAN"
    assert verif["validity_check"]["is_valid"] is True
    assert len(verif["removed_fields"]) > 0
    assert len(verif["remaining_fields"]) == 0

    removed_names = [rf["field"] for rf in verif["removed_fields"]]
    assert "GPS Coordinates" in removed_names
    assert "Author / Artist" in removed_names
