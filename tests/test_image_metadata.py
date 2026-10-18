"""
Tests for GhostData Image Metadata Extraction
"""

import os
from analyzer.image_metadata import extract_image_metadata, _convert_dms_to_decimal


def test_dms_conversion():
    # 37 degrees, 46 minutes, 29.71 seconds North
    dms = (37, 46, 29.71)
    res = _convert_dms_to_decimal(dms, "N")
    assert round(res, 2) == 37.77

    # West ref should be negative
    res_w = _convert_dms_to_decimal(dms, "W")
    assert round(res_w, 2) == -37.77


def test_extract_jpeg_with_gps(sample_dir):
    gps_file = os.path.join(sample_dir, "sample_with_gps.jpg")
    meta = extract_image_metadata(gps_file)

    assert meta["file_type"] == "JPEG"
    assert meta["has_exif"] is True
    assert meta["inspection_status"] == "SUCCESS"

    # GPS checks
    gps = meta["gps"]
    assert gps["has_gps"] is True
    assert abs(gps["latitude"] - 37.77492) < 0.01
    assert abs(gps["longitude"] - (-122.41941)) < 0.01
    assert gps["altitude_meters"] == 45.0
    assert "2024:06:15" in gps["gps_timestamp"]

    # Target fields
    fields = meta["fields"]
    assert fields["camera_device"] == "GhostCamera Corp PrivacyCheck 9000"
    assert fields["lens_model"] == "GhostLens 50mm f/1.8"
    assert fields["device_serial_number"] == "SN-9876543210"
    assert "Jane Doe" in fields["author"]
    assert "2024:06:15 14:30:00" in fields["capture_timestamp"]


def test_extract_clean_jpeg(sample_dir):
    clean_file = os.path.join(sample_dir, "sample_clean.jpg")
    meta = extract_image_metadata(clean_file)

    assert meta["file_type"] == "JPEG"
    assert meta["has_exif"] is False
    assert meta["gps"]["has_gps"] is False
    assert len(meta["fields"]) == 0
