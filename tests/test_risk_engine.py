"""
Tests for GhostData Privacy Risk Explanation Engine
"""

from analyzer.risk_engine import (
    analyze_privacy_risks,
    _mask_coordinates,
    _mask_string,
    Severity
)


def test_coordinate_masking():
    coords = "37.77492° N, 122.41941° W"
    masked = _mask_coordinates(coords)
    assert "37.77***" in masked
    assert "122.41***" in masked


def test_string_masking():
    masked = _mask_string("Jane Doe")
    assert masked.startswith("Ja")
    assert masked.endswith("e")
    assert "*" in masked


def test_risk_analysis_with_gps():
    mock_meta = {
        "file_type": "JPEG",
        "gps": {
            "has_gps": True,
            "latitude": 37.77492,
            "longitude": -122.41941,
            "formatted_coords": "37.77492° N, 122.41941° W",
            "altitude_meters": 45,
            "gps_timestamp": "2024:06:15 14:30:00 UTC",
        },
        "fields": {
            "camera_device": "Sony A7 IV",
            "capture_timestamp": "2024-06-15 14:30:00",
            "author": "SecretAgent",
            "device_serial_number": "SN-12345"
        }
    }

    report = analyze_privacy_risks(mock_meta)
    assert report["overall_risk"] == "HIGH"
    assert report["severity_counts"]["High"] >= 2  # GPS & Serial Number

    fields_found = [f["field"] for f in report["findings"]]
    assert "GPS Coordinates" in fields_found
    assert "Device Serial Number" in fields_found
    assert "Author / Artist" in fields_found

    # Check that explanation and suggested action are populated
    for finding in report["findings"]:
        assert finding["privacy_concern"]
        assert finding["plain_english_explanation"]
        assert finding["suggested_action"]
        assert finding["confidence"]


def test_risk_analysis_clean_file():
    mock_clean = {
        "file_type": "JPEG",
        "gps": {"has_gps": False},
        "fields": {}
    }
    report = analyze_privacy_risks(mock_clean)
    assert report["overall_risk"] == "MINIMAL"
    assert len(report["findings"]) == 0
