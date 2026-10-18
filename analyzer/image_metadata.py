"""
GhostData - Image Metadata Extractor
Extracts EXIF metadata from JPEG files including GPS coordinates, camera information,
capture timestamps, software stamps, and authorship details.
"""

from typing import Dict, Any, Optional, Tuple
from PIL import Image, ExifTags


def _convert_dms_to_decimal(dms_values: Any, ref: str) -> Optional[float]:
    """
    Converts GPS Degrees/Minutes/Seconds coordinates to decimal degrees.
    dms_values is typically a tuple/list: (degrees, minutes, seconds).
    In Pillow modern versions, these are often IFDRational or float/int.
    """
    try:
        if not dms_values or len(dms_values) < 3:
            return None

        # Convert IFDRational or tuples if necessary
        def _to_float(v):
            if hasattr(v, "numerator") and hasattr(v, "denominator"):
                return float(v.numerator) / float(v.denominator) if v.denominator != 0 else 0.0
            if isinstance(v, tuple) and len(v) == 2:
                return float(v[0]) / float(v[1]) if v[1] != 0 else 0.0
            return float(v)

        degrees = _to_float(dms_values[0])
        minutes = _to_float(dms_values[1])
        seconds = _to_float(dms_values[2])

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def _parse_gps_info(gps_dict: Dict[int, Any]) -> Dict[str, Any]:
    """
    Parses EXIF GPSInfo tags into human-readable coordinates, altitude, and timestamp.
    """
    gps_data: Dict[str, Any] = {
        "has_gps": False,
        "latitude": None,
        "longitude": None,
        "altitude_meters": None,
        "gps_timestamp": None,
        "formatted_coords": None,
        "maps_link": None,
    }

    if not gps_dict:
        return gps_data

    # Map tag IDs to tag names
    gps_named_tags = {}
    for tag_id, value in gps_dict.items():
        tag_name = ExifTags.GPSTAGS.get(tag_id, str(tag_id))
        gps_named_tags[tag_name] = value

    lat_dms = gps_named_tags.get("GPSLatitude")
    lat_ref = gps_named_tags.get("GPSLatitudeRef", "N")
    lon_dms = gps_named_tags.get("GPSLongitude")
    lon_ref = gps_named_tags.get("GPSLongitudeRef", "E")

    if lat_dms and lon_dms:
        lat_dec = _convert_dms_to_decimal(lat_dms, lat_ref)
        lon_dec = _convert_dms_to_decimal(lon_dms, lon_ref)

        if lat_dec is not None and lon_dec is not None:
            gps_data["has_gps"] = True
            gps_data["latitude"] = lat_dec
            gps_data["longitude"] = lon_dec
            gps_data["formatted_coords"] = f"{abs(lat_dec):.5f}° {'N' if lat_dec >= 0 else 'S'}, {abs(lon_dec):.5f}° {'E' if lon_dec >= 0 else 'W'}"
            gps_data["maps_link"] = f"https://www.openstreetmap.org/?mlat={lat_dec}&mlon={lon_dec}#map=16/{lat_dec}/{lon_dec}"

    # Altitude
    alt = gps_named_tags.get("GPSAltitude")
    alt_ref = gps_named_tags.get("GPSAltitudeRef", 0)  # 0 = above sea level, 1 = below sea level
    if alt is not None:
        try:
            if hasattr(alt, "numerator") and hasattr(alt, "denominator"):
                alt_m = float(alt.numerator) / float(alt.denominator) if alt.denominator != 0 else 0.0
            elif isinstance(alt, tuple) and len(alt) == 2:
                alt_m = float(alt[0]) / float(alt[1]) if alt[1] != 0 else 0.0
            else:
                alt_m = float(alt)
            if alt_ref == 1:
                alt_m = -alt_m
            gps_data["altitude_meters"] = round(alt_m, 2)
        except Exception:
            pass

    # GPS Date/Time
    gps_date = gps_named_tags.get("GPSDateStamp")
    gps_time = gps_named_tags.get("GPSTimeStamp")
    if gps_date:
        try:
            if gps_time and len(gps_time) == 3:
                h = int(gps_time[0])
                m = int(gps_time[1])
                s = int(gps_time[2])
                gps_data["gps_timestamp"] = f"{gps_date} {h:02d}:{m:02d}:{s:02d} UTC"
            else:
                gps_data["gps_timestamp"] = str(gps_date)
        except Exception:
            gps_data["gps_timestamp"] = str(gps_date)

    return gps_data


def extract_image_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extracts all discernible metadata from a JPEG file.
    Distinguishes fields that are present, empty, or failed inspection.
    """
    result: Dict[str, Any] = {
        "file_type": "JPEG",
        "has_exif": False,
        "inspection_status": "SUCCESS",
        "inspection_error": None,
        "fields": {},
        "raw_exif_tags": {},
        "gps": {
            "has_gps": False,
            "latitude": None,
            "longitude": None,
            "altitude_meters": None,
            "gps_timestamp": None,
            "formatted_coords": None,
            "maps_link": None,
        },
        "dimensions": None,
        "color_mode": None,
    }

    try:
        with Image.open(file_path) as img:
            result["dimensions"] = f"{img.width}x{img.height}"
            result["color_mode"] = img.mode

            # Extract EXIF if available
            exif_obj = img.getexif()
            if not exif_obj or len(exif_obj) == 0:
                result["has_exif"] = False
                return result

            result["has_exif"] = True

            # Standard EXIF tags
            exif_dict = {}
            for tag_id, value in exif_obj.items():
                tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                # Convert bytes or large unprintable buffers to strings
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace").strip("\x00")
                    except Exception:
                        value = f"<binary data: {len(value)} bytes>"
                exif_dict[tag_name] = value

            # EXIF SubIFD (contains DateTimeOriginal, LensModel, etc.)
            try:
                if hasattr(ExifTags, "IFD") and hasattr(ExifTags.IFD, "Exif"):
                    sub_ifd = exif_obj.get_ifd(ExifTags.IFD.Exif)
                    for sub_id, sub_val in sub_ifd.items():
                        tag_name = ExifTags.TAGS.get(sub_id, f"Exif_{sub_id}")
                        if isinstance(sub_val, bytes):
                            try:
                                sub_val = sub_val.decode("utf-8", errors="replace").strip("\x00")
                            except Exception:
                                sub_val = f"<binary data: {len(sub_val)} bytes>"
                        exif_dict[tag_name] = sub_val
            except Exception:
                pass

            # GPS IFD
            try:
                gps_ifd = None
                if hasattr(ExifTags, "IFD") and hasattr(ExifTags.IFD, "GPSInfo"):
                    gps_ifd = exif_obj.get_ifd(ExifTags.IFD.GPSInfo)
                elif "GPSInfo" in exif_dict and isinstance(exif_dict["GPSInfo"], dict):
                    gps_ifd = exif_dict["GPSInfo"]

                if gps_ifd:
                    result["gps"] = _parse_gps_info(gps_ifd)
            except Exception as gps_exc:
                result["gps"]["inspection_error"] = str(gps_exc)

            result["raw_exif_tags"] = {k: str(v) for k, v in exif_dict.items() if k != "GPSInfo"}

            # Map into structured target fields
            fields = {}

            # 1. Capture Dates
            date_orig = exif_dict.get("DateTimeOriginal") or exif_dict.get("DateTimeDigitized") or exif_dict.get("DateTime")
            if date_orig:
                fields["capture_timestamp"] = str(date_orig).strip()

            # 2. Camera Hardware
            make = exif_dict.get("Make")
            model = exif_dict.get("Model")
            if make or model:
                camera_str = " ".join(filter(None, [str(make).strip() if make else "", str(model).strip() if model else ""]))
                fields["camera_device"] = camera_str

            lens = exif_dict.get("LensModel") or exif_dict.get("LensMake")
            if lens:
                fields["lens_model"] = str(lens).strip()

            body_serial = exif_dict.get("BodySerialNumber") or exif_dict.get("SerialNumber")
            if body_serial:
                fields["device_serial_number"] = str(body_serial).strip()

            # 3. Software
            software = exif_dict.get("Software") or exif_dict.get("ProcessingSoftware")
            if software:
                fields["software"] = str(software).strip()

            # 4. Authorship & Copyright
            artist = exif_dict.get("Artist") or exif_dict.get("XPAuthor")
            if artist:
                fields["author"] = str(artist).strip()

            copyright_notice = exif_dict.get("Copyright")
            if copyright_notice:
                fields["copyright"] = str(copyright_notice).strip()

            # 5. User Comments
            user_comment = exif_dict.get("UserComment") or exif_dict.get("XPComment")
            if user_comment:
                fields["user_comment"] = str(user_comment).strip()

            # 6. Technical capture parameters
            exposure = exif_dict.get("ExposureTime")
            f_number = exif_dict.get("FNumber")
            iso = exif_dict.get("ISOSpeedRatings") or exif_dict.get("PhotographicSensitivity")
            focal_len = exif_dict.get("FocalLength")
            orientation = exif_dict.get("Orientation")

            tech_details = []
            if exposure:
                tech_details.append(f"Exposure: {exposure}s")
            if f_number:
                tech_details.append(f"f/{f_number}")
            if iso:
                tech_details.append(f"ISO {iso}")
            if focal_len:
                tech_details.append(f"{focal_len}mm")
            if tech_details:
                fields["camera_settings"] = ", ".join(tech_details)
            if orientation:
                fields["orientation_tag"] = str(orientation)

            result["fields"] = fields

    except Exception as exc:
        result["inspection_status"] = "FAILED"
        result["inspection_error"] = str(exc)

    return result
