"""
GhostData - Privacy Risk Explanation Engine
Evaluates extracted metadata using a rule-based privacy rubric.
Produces evidence-based findings, masked previews, severity ratings,
and plain-English remediation advice.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class RiskFinding:
    field: str
    category: str  # "Location", "Identity", "Timeline & Activity", "Technical Fingerprint"
    raw_value: str
    masked_value: str
    severity: Severity
    privacy_concern: str
    plain_english_explanation: str
    suggested_action: str
    confidence: str


def _mask_coordinates(coords_str: Optional[str]) -> str:
    """
    Partially masks GPS coordinates to protect location while showing presence.
    Example: '37.77492° N, 122.41941° W' -> '37.77*** N, 122.41*** W'
    """
    if not coords_str:
        return "[Hidden Coordinates]"
    try:
        parts = coords_str.split(",")
        masked_parts = []
        for part in parts:
            part = part.strip()
            tokens = part.split(".")
            if len(tokens) == 2:
                int_part = tokens[0]
                rest = tokens[1]
                # keep 2 decimals, mask rest
                dec_digits = "".join([c for c in rest if c.isdigit()])
                non_digits = "".join([c for c in rest if not c.isdigit()])
                masked_dec = dec_digits[:2] + ("*" * max(1, len(dec_digits) - 2))
                masked_parts.append(f"{int_part}.{masked_dec}{non_digits}")
            else:
                masked_parts.append(part)
        return ", ".join(masked_parts)
    except Exception:
        return "[Coordinates Masked]"


def _mask_string(value: str, keep_start: int = 2, keep_end: int = 1) -> str:
    """
    Masks middle characters of an identifier or name.
    """
    if not value or len(value) <= 3:
        return "***"
    if len(value) <= keep_start + keep_end:
        return value[0] + ("*" * (len(value) - 1))
    return value[:keep_start] + ("*" * (len(value) - keep_start - keep_end)) + value[-keep_end:]


def analyze_privacy_risks(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes extracted metadata dictionary (from image_metadata or pdf_metadata)
    and produces a comprehensive risk report with clear justifications.
    """
    findings: List[RiskFinding] = []
    file_type = metadata.get("file_type", "UNKNOWN")

    # 1. GPS Analysis (JPEGs)
    gps = metadata.get("gps", {})
    if gps.get("has_gps"):
        lat = gps.get("latitude")
        lon = gps.get("longitude")
        coords_str = gps.get("formatted_coords", f"{lat}, {lon}")
        masked_coords = _mask_coordinates(coords_str)
        alt = gps.get("altitude_meters")
        alt_str = f" (Altitude: {alt}m)" if alt is not None else ""

        findings.append(RiskFinding(
            field="GPS Coordinates",
            category="Location",
            raw_value=f"{coords_str}{alt_str}",
            masked_value=f"{masked_coords}{alt_str}",
            severity=Severity.HIGH,
            privacy_concern="Exposes the exact geographic location and altitude where the photograph was captured.",
            plain_english_explanation=(
                "Modern smartphones and cameras record latitude and longitude coordinates with high precision "
                "(often accurate to a few meters). If you share this image online or send it to an acquaintance, "
                "anyone can map your home, office, school, or travel habits."
            ),
            suggested_action="Strip EXIF geolocation tags before publishing or sharing this photo.",
            confidence="High (Verified from EXIF GPSInfo IFD tags 0x0002 and 0x0004)"
        ))

        if gps.get("gps_timestamp"):
            findings.append(RiskFinding(
                field="GPS Satellite Timestamp",
                category="Timeline & Activity",
                raw_value=gps["gps_timestamp"],
                masked_value=gps["gps_timestamp"],
                severity=Severity.MEDIUM,
                privacy_concern="Reveals an independent atomic clock timestamp synchronized with GPS satellites.",
                plain_english_explanation=(
                    "GPS receivers record their own atomic satellite time independently of the camera's system clock. "
                    "This establishes an unforgeable timestamp of when you were at that specific location."
                ),
                suggested_action="Remove all GPS tags during cleaning.",
                confidence="High (Verified from EXIF GPSTimeStamp tag)"
            ))

    # 2. General Fields
    fields = metadata.get("fields", {})

    # Authorship / Identity
    if "author" in fields:
        raw_author = fields["author"]
        masked_author = _mask_string(raw_author)
        findings.append(RiskFinding(
            field="Author / Artist",
            category="Identity",
            raw_value=raw_author,
            masked_value=masked_author,
            severity=Severity.HIGH if ("@" in raw_author or "\\" in raw_author or "/" in raw_author) else Severity.MEDIUM,
            privacy_concern="Reveals the real name, login handle, or workstation identity of the file creator.",
            plain_english_explanation=(
                f"The file explicitly embeds '{raw_author}' in its creator metadata. "
                "In workplace documents or public images, this directly connects anonymous uploads back to a specific individual."
            ),
            suggested_action="Remove author tags to preserve anonymity when sharing externally.",
            confidence=f"Verified from {'EXIF Artist/XPAuthor tag' if file_type == 'JPEG' else 'PDF /Author property or XMP creator'}"
        ))

    # Device Serial Numbers
    if "device_serial_number" in fields:
        raw_serial = fields["device_serial_number"]
        findings.append(RiskFinding(
            field="Device Serial Number",
            category="Identity",
            raw_value=raw_serial,
            masked_value=_mask_string(raw_serial, 2, 2),
            severity=Severity.HIGH,
            privacy_concern="Unique hardware serial numbers enable persistent cross-document device tracking.",
            plain_english_explanation=(
                "Your camera or lens embeds its unique factory serial number. Investigators and web scrapers "
                "can link multiple photos taken on different days or posted under different pseudonyms to the exact same physical camera."
            ),
            suggested_action="Sanitize EXIF maker notes and serial fields immediately.",
            confidence="High (Verified from EXIF BodySerialNumber tag)"
        ))

    # Capture / Creation Timestamp
    date_field = "capture_timestamp" if file_type == "JPEG" else "creation_date"
    if date_field in fields:
        raw_date = fields[date_field]
        findings.append(RiskFinding(
            field="Capture / Creation Date",
            category="Timeline & Activity",
            raw_value=raw_date,
            masked_value=raw_date,
            severity=Severity.LOW,
            privacy_concern="Reveals the exact date and time when the file was generated or captured.",
            plain_english_explanation=(
                "While not an immediate security exploit, timestamps disclose your daily routines, "
                "working hours, time zones, or weekend travel schedule. In legal or confidential contexts, "
                "it can contradict or verify activity timelines."
            ),
            suggested_action="Clear creation timestamps if document drafting timeline is confidential.",
            confidence="Verified from timestamp metadata headers"
        ))

    # Modification Date
    if "modification_date" in fields:
        raw_mod = fields["modification_date"]
        findings.append(RiskFinding(
            field="Last Modified Date",
            category="Timeline & Activity",
            raw_value=raw_mod,
            masked_value=raw_mod,
            severity=Severity.LOW,
            privacy_concern="Shows the date and time when the document was last edited or re-saved.",
            plain_english_explanation=(
                "Discloses the revision history timeline and indicates when modifications took place."
            ),
            suggested_action="Clear modification timestamps when publishing the final version.",
            confidence="Verified from PDF /ModDate metadata"
        ))

    # Camera Device / Model
    if "camera_device" in fields:
        raw_cam = fields["camera_device"]
        findings.append(RiskFinding(
            field="Camera Hardware",
            category="Technical Fingerprint",
            raw_value=raw_cam,
            masked_value=raw_cam,
            severity=Severity.LOW,
            privacy_concern="Identifies the specific make and model of the phone or camera used.",
            plain_english_explanation=(
                f"Identifies that the photo was captured with '{raw_cam}'. While generally low risk, "
                "this hardware fingerprint narrows down personal device ownership and device tier."
            ),
            suggested_action="Strip EXIF camera hardware tags for cleaner privacy posture.",
            confidence="Verified from EXIF Make/Model tags"
        ))

    # Software / Tools
    soft_field = "software" if file_type == "JPEG" else "creator_application"
    if soft_field in fields:
        raw_soft = fields[soft_field]
        findings.append(RiskFinding(
            field="Editing Software / Generator",
            category="Technical Fingerprint",
            raw_value=raw_soft,
            masked_value=raw_soft,
            severity=Severity.LOW,
            privacy_concern="Reveals the software application, version, or workflow pipeline used to produce the file.",
            plain_english_explanation=(
                f"Reports that the file was generated or edited using '{raw_soft}'. "
                "Security researchers note that outdated software versions reported in metadata can highlight "
                "potential unpatched vulnerabilities in a creator's operating environment."
            ),
            suggested_action="Remove software tags to avoid exposing software vendor information.",
            confidence="Verified from application creator headers"
        ))

    # Producer Software (PDF)
    if "producer_software" in fields:
        raw_prod = fields["producer_software"]
        if raw_prod != fields.get("creator_application"):
            findings.append(RiskFinding(
                field="PDF Producer Engine",
                category="Technical Fingerprint",
                raw_value=raw_prod,
                masked_value=raw_prod,
                severity=Severity.LOW,
                privacy_concern="Discloses the underlying PDF rendering library or print driver.",
                plain_english_explanation=(
                    f"Discloses that '{raw_prod}' compiled the final document format."
                ),
                suggested_action="Strip producer metadata.",
                confidence="Verified from PDF /Producer header"
            ))

    # Title / Subject / Keywords (PDF)
    if "title" in fields:
        findings.append(RiskFinding(
            field="Document Title",
            category="Identity",
            raw_value=fields["title"],
            masked_value=fields["title"],
            severity=Severity.MEDIUM,
            privacy_concern="Embedded title property may expose internal project codes, previous drafts, or confidential labels.",
            plain_english_explanation=(
                f"Document title is set to '{fields['title']}'. Many office suites automatically retain old or internal working titles."
            ),
            suggested_action="Verify or remove the title property before external distribution.",
            confidence="Verified from PDF /Title dictionary entry"
        ))

    if "keywords" in fields:
        findings.append(RiskFinding(
            field="Embedded Keywords / Tags",
            category="Identity",
            raw_value=fields["keywords"],
            masked_value=fields["keywords"],
            severity=Severity.LOW,
            privacy_concern="Discloses categorization tags or internal topic markers.",
            plain_english_explanation="Internal filing keywords remain attached to the document stream.",
            suggested_action="Remove keywords prior to sharing.",
            confidence="Verified from PDF /Keywords property"
        ))

    # User comments / Copyright
    if "user_comment" in fields:
        findings.append(RiskFinding(
            field="User Comment",
            category="Identity",
            raw_value=fields["user_comment"],
            masked_value=fields["user_comment"],
            severity=Severity.LOW,
            privacy_concern="Contains freeform textual comments or annotations injected during capture.",
            plain_english_explanation="Discloses notes or comments stored in the EXIF container.",
            suggested_action="Strip comment fields.",
            confidence="Verified from EXIF UserComment tag"
        ))

    # Structural warnings (PDF annotations / attachments)
    structures = metadata.get("structures_detected", {})
    if structures.get("has_annotations"):
        findings.append(RiskFinding(
            field="PDF Annotations",
            category="Structural Warning",
            raw_value="Annotations / Comments Present",
            masked_value="Annotations / Comments Present",
            severity=Severity.MEDIUM,
            privacy_concern="PDF contains page annotations, comments, or highlight objects that might contain reviewer notes.",
            plain_english_explanation=(
                "Annotations and sticky notes in PDFs can contain author remarks or deleted drafts that aren't removed "
                "by basic header sanitization alone."
            ),
            suggested_action="Review and flatten annotations if the document underwent internal review.",
            confidence="Detected /Annots array in document page objects"
        ))

    if structures.get("has_embedded_files"):
        findings.append(RiskFinding(
            field="Embedded Files / Attachments",
            category="Structural Warning",
            raw_value="Embedded files detected in PDF catalog",
            masked_value="Embedded files detected in PDF catalog",
            severity=Severity.HIGH,
            privacy_concern="PDF has files embedded inside it that could contain hidden or uninspected data.",
            plain_english_explanation=(
                "PDF packages can embed arbitrary secondary files. These attached files are separate documents "
                "with their own metadata and contents."
            ),
            suggested_action="Inspect PDF attachments manually before publishing.",
            confidence="Detected /EmbeddedFiles dictionary in PDF root"
        ))

    # Calculate overall risk score
    severity_counts = {
        "High": sum(1 for f in findings if f.severity == Severity.HIGH),
        "Medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
        "Low": sum(1 for f in findings if f.severity == Severity.LOW),
        "Informational": sum(1 for f in findings if f.severity == Severity.INFO),
    }

    if severity_counts["High"] > 0:
        overall_risk = "HIGH"
        risk_summary = f"High Privacy Risk: Detected {severity_counts['High']} critical exposure(s) including location, direct identity, or embedded payloads."
    elif severity_counts["Medium"] > 0:
        overall_risk = "MEDIUM"
        risk_summary = f"Medium Privacy Risk: Detected {severity_counts['Medium']} identifying item(s) such as creator name, titles, or annotations."
    elif severity_counts["Low"] > 0:
        overall_risk = "LOW"
        risk_summary = f"Low Privacy Risk: Minor technical footprints detected (e.g. timestamps, camera/software labels). No direct personal identity or location."
    else:
        overall_risk = "MINIMAL"
        risk_summary = "Minimal Privacy Risk: No significant metadata or tracking footprints were detected in this file."

    return {
        "file_type": file_type,
        "overall_risk": overall_risk,
        "risk_summary": risk_summary,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings]
    }
