"""
GhostData - PDF Metadata Extractor
Extracts Document Information Dictionary and XMP metadata from PDF files using pypdf.
"""

import re
from typing import Dict, Any, Optional
from pypdf import PdfReader


def _parse_pdf_date(date_str: Optional[str]) -> Optional[str]:
    """
    Parses PDF date format D:YYYYMMDDHHmmSSOHH'mm' into an ISO-like or readable string.
    Example: 'D:20240315143000+02\'00\'' -> '2024-03-15 14:30:00 (+02:00)'
    """
    if not date_str:
        return None
    try:
        raw = str(date_str).strip()
        if raw.startswith("D:"):
            raw = raw[2:]

        pattern = r"^(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([+\-Z])?(\d{2})?'?(\d{2})?'?"
        match = re.match(pattern, raw)
        if match:
            year, month, day, hour, minute, second, tz_sign, tz_hour, tz_min = match.groups()
            parts = [year]
            if month:
                parts.append(f"-{month}")
            if day:
                parts.append(f"-{day}")
            formatted = "".join(parts)

            time_parts = []
            if hour:
                time_parts.append(hour)
                if minute:
                    time_parts.append(f":{minute}")
                if second:
                    time_parts.append(f":{second}")
            if time_parts:
                formatted += " " + "".join(time_parts)

            if tz_sign:
                if tz_sign == "Z":
                    formatted += " UTC"
                elif tz_hour:
                    formatted += f" (UTC{tz_sign}{tz_hour}:{tz_min or '00'})"

            return formatted
        return str(date_str)
    except Exception:
        return str(date_str)


def extract_pdf_metadata(file_path: str) -> Dict[str, Any]:
    """
    Inspects PDF Document Information Dictionary, XMP streams, page counts,
    and potential areas where residual metadata or sensitive structures may exist.
    """
    result: Dict[str, Any] = {
        "file_type": "PDF",
        "has_metadata": False,
        "inspection_status": "SUCCESS",
        "inspection_error": None,
        "page_count": 0,
        "is_encrypted": False,
        "fields": {},
        "raw_doc_info": {},
        "xmp_metadata": {},
        "structures_detected": {
            "has_annotations": False,
            "has_attachments": False,
            "has_embedded_files": False,
            "has_forms": False,
        },
    }

    try:
        reader = PdfReader(file_path, strict=False)
        result["page_count"] = len(reader.pages)
        result["is_encrypted"] = reader.is_encrypted

        # Document Information Dictionary
        doc_info = reader.metadata
        raw_info = {}
        if doc_info:
            for k, v in doc_info.items():
                if v is not None:
                    clean_k = str(k).lstrip("/")
                    raw_info[clean_k] = str(v).strip()

        result["raw_doc_info"] = raw_info

        # Extract standard fields
        fields = {}
        if raw_info.get("Author"):
            fields["author"] = raw_info["Author"]
        if raw_info.get("Creator"):
            fields["creator_application"] = raw_info["Creator"]
        if raw_info.get("Producer"):
            fields["producer_software"] = raw_info["Producer"]
        if raw_info.get("Title"):
            fields["title"] = raw_info["Title"]
        if raw_info.get("Subject"):
            fields["subject"] = raw_info["Subject"]
        if raw_info.get("Keywords"):
            fields["keywords"] = raw_info["Keywords"]
        if raw_info.get("CreationDate"):
            fields["creation_date"] = _parse_pdf_date(raw_info["CreationDate"])
        if raw_info.get("ModDate"):
            fields["modification_date"] = _parse_pdf_date(raw_info["ModDate"])

        # XMP Metadata extraction
        xmp_dict = {}
        try:
            xmp = reader.xmp_metadata
            if xmp:
                # Common XMP attributes
                for attr in ["dc_creator", "dc_title", "dc_description", "dc_date",
                             "xmp_create_date", "xmp_modify_date", "xmp_creator_tool",
                             "pdf_producer", "pdf_keywords"]:
                    if hasattr(xmp, attr):
                        val = getattr(xmp, attr)
                        if val:
                            if isinstance(val, (list, tuple)):
                                val = ", ".join(str(item) for item in val if item)
                            xmp_dict[attr] = str(val)

                # Merge into fields if missing in standard info
                if "author" not in fields and xmp_dict.get("dc_creator"):
                    fields["author"] = xmp_dict["dc_creator"]
                if "creator_application" not in fields and xmp_dict.get("xmp_creator_tool"):
                    fields["creator_application"] = xmp_dict["xmp_creator_tool"]
                if "producer_software" not in fields and xmp_dict.get("pdf_producer"):
                    fields["producer_software"] = xmp_dict["pdf_producer"]
                if "title" not in fields and xmp_dict.get("dc_title"):
                    fields["title"] = xmp_dict["dc_title"]
        except Exception:
            # XMP parsing can fail if malformed; record empty
            pass

        result["xmp_metadata"] = xmp_dict

        # Detect structural elements (annotations, attachments)
        try:
            annotations_found = False
            for page in reader.pages:
                if "/Annots" in page and page["/Annots"]:
                    annotations_found = True
                    break
            result["structures_detected"]["has_annotations"] = annotations_found

            # Check Root for /Names, /EmbeddedFiles, /AcroForm
            root = reader.trailer.get("/Root") if hasattr(reader, "trailer") and reader.trailer else None
            if root and hasattr(root, "get_object"):
                root_obj = root.get_object()
                if "/Names" in root_obj and "/EmbeddedFiles" in root_obj["/Names"]:
                    result["structures_detected"]["has_embedded_files"] = True
                if "/AcroForm" in root_obj:
                    result["structures_detected"]["has_forms"] = True
        except Exception:
            pass

        result["fields"] = fields
        result["has_metadata"] = bool(fields or raw_info or xmp_dict)

    except Exception as exc:
        result["inspection_status"] = "FAILED"
        result["inspection_error"] = str(exc)

    return result
