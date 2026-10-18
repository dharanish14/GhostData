"""
Tests for GhostData PDF Metadata Extraction
"""

import os
from analyzer.pdf_metadata import extract_pdf_metadata, _parse_pdf_date


def test_pdf_date_parsing():
    raw_date = "D:20240615143000+00'00'"
    parsed = _parse_pdf_date(raw_date)
    assert "2024-06-15" in parsed
    assert "14:30:00" in parsed


def test_extract_pdf_with_metadata(sample_dir):
    meta_pdf = os.path.join(sample_dir, "sample_with_metadata.pdf")
    meta = extract_pdf_metadata(meta_pdf)

    assert meta["file_type"] == "PDF"
    assert meta["has_metadata"] is True
    assert meta["inspection_status"] == "SUCCESS"
    assert meta["page_count"] == 1

    fields = meta["fields"]
    assert "Alice Smith" in fields["author"]
    assert "GhostData PDF Generator" in fields["creator_application"]
    assert "Internal Enterprise Publishing Suite" in fields["producer_software"]
    assert "Internal Project Falcon Architecture" in fields["title"]
    assert "Confidential Technical Specification" in fields["subject"]
    assert "internal, architecture, classified" in fields["keywords"]
    assert "2024-06-15" in fields["creation_date"]


def test_extract_clean_pdf(sample_dir):
    clean_pdf = os.path.join(sample_dir, "sample_clean.pdf")
    meta = extract_pdf_metadata(clean_pdf)

    assert meta["file_type"] == "PDF"
    assert meta["inspection_status"] == "SUCCESS"
    assert len(meta["fields"]) == 0
