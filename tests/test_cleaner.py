"""
Tests for GhostData Metadata Cleaner
"""

import os
from PIL import Image
from pypdf import PdfReader
from analyzer.cleaner import clean_file
from analyzer.image_metadata import extract_image_metadata
from analyzer.pdf_metadata import extract_pdf_metadata


def test_clean_jpeg_preserves_original_and_strips_metadata(sample_dir, tmp_path):
    orig_jpg = os.path.join(sample_dir, "sample_with_gps.jpg")
    orig_size = os.path.getsize(orig_jpg)

    clean_dir = str(tmp_path / "cleaned")
    clean_name, clean_path, details = clean_file(orig_jpg, "JPEG", clean_dir)

    # 1. Original file is NOT overwritten
    assert os.path.getsize(orig_jpg) == orig_size

    # 2. Cleaned file exists and is separate
    assert os.path.exists(clean_path)
    assert clean_path != orig_jpg

    # 3. Cleaned image can be opened and has valid visual dimensions
    with Image.open(clean_path) as img:
        assert img.size == (400, 300)

    # 4. Cleaned image has ZERO EXIF or GPS
    clean_meta = extract_image_metadata(clean_path)
    assert clean_meta["has_exif"] is False
    assert clean_meta["gps"]["has_gps"] is False
    assert len(clean_meta["fields"]) == 0


def test_clean_pdf_preserves_original_and_strips_metadata(sample_dir, tmp_path):
    orig_pdf = os.path.join(sample_dir, "sample_with_metadata.pdf")
    orig_size = os.path.getsize(orig_pdf)

    clean_dir = str(tmp_path / "cleaned")
    clean_name, clean_path, details = clean_file(orig_pdf, "PDF", clean_dir)

    # 1. Original untouched
    assert os.path.getsize(orig_pdf) == orig_size

    # 2. Cleaned file valid PDF
    reader = PdfReader(clean_path)
    assert len(reader.pages) == 1

    # 3. Cleaned metadata extraction yields zero sensitive author/title
    clean_meta = extract_pdf_metadata(clean_path)
    assert "author" not in clean_meta["fields"]
    assert "title" not in clean_meta["fields"]
