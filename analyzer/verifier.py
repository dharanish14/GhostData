"""
GhostData - Post-Cleaning Verification Engine
Re-scans cleaned files, verifies structural validity, and performs an evidence-based
field-by-field diff between original and sanitized outputs.
"""

from typing import Dict, Any, List
from PIL import Image
from pypdf import PdfReader
from .image_metadata import extract_image_metadata
from .pdf_metadata import extract_pdf_metadata
from .risk_engine import analyze_privacy_risks


def verify_file_validity(file_path: str, file_type: str) -> Dict[str, Any]:
    """
    Confirms that the sanitized file can still be opened and parsed
    by standard viewers without corruption.
    """
    validity = {
        "is_valid": False,
        "can_open": False,
        "details": "",
        "error": None,
    }

    try:
        if file_type.upper() == "JPEG":
            with Image.open(file_path) as img:
                img.verify()
            with Image.open(file_path) as img:
                validity["is_valid"] = True
                validity["can_open"] = True
                validity["details"] = f"Valid JPEG image ({img.width}x{img.height}, {img.mode} mode)"
        elif file_type.upper() == "PDF":
            reader = PdfReader(file_path, strict=False)
            pages = len(reader.pages)
            if pages >= 0:
                validity["is_valid"] = True
                validity["can_open"] = True
                validity["details"] = f"Valid PDF document ({pages} page{'s' if pages != 1 else ''})"
            else:
                validity["is_valid"] = False
                validity["details"] = "PDF reader could not read pages."
        else:
            validity["error"] = f"Unknown file type: {file_type}"
    except Exception as exc:
        validity["is_valid"] = False
        validity["can_open"] = False
        validity["error"] = str(exc)

    return validity


def verify_cleaning(
    original_metadata: Dict[str, Any],
    original_risk: Dict[str, Any],
    cleaned_file_path: str,
    file_type: str,
    cleaner_notes: List[str],
    unsupported_structures: List[str]
) -> Dict[str, Any]:
    """
    Performs complete verification:
    1. Tests structural validity of the generated file.
    2. Runs second-pass extraction on the cleaned file.
    3. Analyzes post-clean privacy risks.
    4. Computes itemized field-by-field comparison (Removed, Remaining, Unverified).
    5. Sets verified status based ONLY on actual evidence, never on cleaner completion alone.
    """
    # 1. Structural validity
    validity = verify_file_validity(cleaned_file_path, file_type)

    # 2. Second-pass extraction
    if file_type.upper() == "JPEG":
        post_metadata = extract_image_metadata(cleaned_file_path)
    elif file_type.upper() == "PDF":
        post_metadata = extract_pdf_metadata(cleaned_file_path)
    else:
        post_metadata = {"fields": {}, "inspection_status": "FAILED", "inspection_error": "Unsupported type"}

    # 3. Second-pass risk analysis
    post_risk = analyze_privacy_risks(post_metadata)

    # 4. Itemized comparison
    removed_fields = []
    remaining_fields = []
    unverified_fields = []

    # Map original findings
    orig_findings = original_risk.get("findings", [])
    post_findings = post_risk.get("findings", [])

    post_finding_fields = {f["field"]: f for f in post_findings}

    for orig_f in orig_findings:
        field_name = orig_f["field"]
        if field_name in post_finding_fields:
            # Field was NOT removed
            remaining_fields.append({
                "field": field_name,
                "category": orig_f["category"],
                "original_value": orig_f["masked_value"],
                "cleaned_value": post_finding_fields[field_name]["masked_value"],
                "severity": post_finding_fields[field_name]["severity"],
                "reason": "Still present in sanitized file"
            })
        else:
            # Field successfully removed
            removed_fields.append({
                "field": field_name,
                "category": orig_f["category"],
                "original_value": orig_f["masked_value"],
                "status": "Verified Removed",
                "evidence": f"No longer detected in {file_type} inspection"
            })

    # Unsupported / unverified structures
    for item in unsupported_structures:
        unverified_fields.append({
            "structure": item,
            "status": "Unverified / Preserved",
            "reason": "Requires deep document reconstruction or risks content alteration."
        })

    # 5. Determine Overall Verification Decision
    # Only verify if file is valid AND target high-risk metadata is eliminated
    is_verified_clean = (
        validity["is_valid"] and
        len([rf for rf in remaining_fields if rf["severity"] in ("High", "Medium")]) == 0
    )

    if not validity["is_valid"]:
        verification_status = "FAILED_CORRUPT"
        verdict_summary = "Verification Failed: The generated file cannot be parsed or opened."
    elif remaining_fields:
        verification_status = "PARTIAL"
        verdict_summary = f"Partial Sanitization: {len(removed_fields)} fields removed, but {len(remaining_fields)} fields remain."
    elif len(orig_findings) == 0:
        verification_status = "CLEAN_UNCHANGED"
        verdict_summary = "Verified: Original file already contained no targeted metadata; output remains clean and valid."
    else:
        verification_status = "VERIFIED_CLEAN"
        verdict_summary = f"Verified Clean: All {len(removed_fields)} detected metadata fields were confirmed removed. Output file is valid and readable."

    return {
        "is_verified_clean": is_verified_clean,
        "verification_status": verification_status,
        "verdict_summary": verdict_summary,
        "validity_check": validity,
        "original_findings_count": len(orig_findings),
        "post_clean_findings_count": len(post_findings),
        "removed_fields": removed_fields,
        "remaining_fields": remaining_fields,
        "unverified_fields": unverified_fields,
        "cleaner_notes": cleaner_notes,
        "post_clean_risk": post_risk
    }
