"""
GhostData - Metadata Sanitizer / Cleaner
Safely removes metadata from JPEG images and PDF documents without modifying the original file.
Preserves image orientation, visual fidelity, and document structure.
"""

import os
import uuid
from typing import Dict, Any, Tuple, List
from PIL import Image, ImageOps
from pypdf import PdfReader, PdfWriter


class CleaningError(Exception):
    """Raised when metadata cleaning fails."""
    pass


def clean_jpeg(input_path: str, output_path: str) -> Dict[str, Any]:
    """
    Sanitizes JPEG images:
    1. Reads original image pixels.
    2. Transposes pixels according to EXIF orientation tag so the physical pixel
       matrix matches visual orientation before the EXIF orientation tag is dropped.
    3. Converts image to RGB mode if necessary.
    4. Re-encodes image to a new file WITHOUT embedding any EXIF, IPTC, or XMP chunks.
    5. Preserves visual fidelity (JPEG quality 95, subsampling 0).
    """
    try:
        with Image.open(input_path) as img:
            # Step 1 & 2: Normalize orientation based on EXIF tag before stripping
            transposed_img = ImageOps.exif_transpose(img)
            if transposed_img is None:
                transposed_img = img.copy()

            # Ensure image is in a standard color mode for JPEG saving
            if transposed_img.mode not in ("RGB", "L"):
                transposed_img = transposed_img.convert("RGB")

            # Step 4 & 5: Save directly without passing exif=... or info['exif']
            # Pillow's default save will not include EXIF unless specifically passed
            transposed_img.save(
                output_path,
                format="JPEG",
                quality=95,
                optimize=True,
                subsampling=0
            )

        return {
            "success": True,
            "method": "Image raster re-encoding with EXIF transposition and complete metadata strip",
            "notes": [
                "EXIF, IPTC, and XMP metadata chunks were completely excluded during re-encoding.",
                "Visual image orientation was permanently baked into the pixel grid before removing EXIF orientation tags.",
                "Image was re-encoded at high quality (95%) with 4:4:4 color subsampling to minimize compression artifacts."
            ],
            "unsupported_structures": []
        }
    except Exception as exc:
        raise CleaningError(f"JPEG cleaning failed: {exc}")


def clean_pdf(input_path: str, output_path: str) -> Dict[str, Any]:
    """
    Sanitizes PDF documents:
    1. Reads PDF structure with pypdf.
    2. Copies all page objects, fonts, vector drawings, and resources into a fresh PdfWriter.
    3. Strips the Document Information Dictionary (/Info).
    4. Strips the XMP Metadata Stream (/Metadata) from the document catalog (/Root).
    5. Saves output as a newly compiled PDF.
    6. Returns warnings regarding structures that cannot be automatically scrubbed without risking document layout.
    """
    warnings: List[str] = []
    unsupported_structures: List[str] = []

    try:
        reader = PdfReader(input_path, strict=False)
        writer = PdfWriter()

        # Check for annotations or attachments before writing
        for idx, page in enumerate(reader.pages):
            writer.add_page(page)
            if "/Annots" in page and page["/Annots"]:
                warnings.append(f"Page {idx + 1} contains annotations that may contain text or author comments.")
                unsupported_structures.append(f"Annotations on page {idx + 1}")

        # Check for embedded files
        root = reader.trailer.get("/Root") if hasattr(reader, "trailer") and reader.trailer else None
        if root and hasattr(root, "get_object"):
            root_obj = root.get_object()
            if "/Names" in root_obj and "/EmbeddedFiles" in root_obj["/Names"]:
                warnings.append("Document contains embedded file attachments. These attachments were preserved but their internal metadata was not sanitized.")
                unsupported_structures.append("Embedded Files / Attachments")

        # Strip standard document information dictionary completely
        # Setting _info to None prevents pypdf from injecting its default /Producer tag
        writer._info = None

        # Strip XMP Metadata from catalog root if present
        if "/Metadata" in writer._root_object:
            del writer._root_object["/Metadata"]

        # Write clean PDF to destination
        with open(output_path, "wb") as f_out:
            writer.write(f_out)

        notes = [
            "Document Information Dictionary (/Author, /Creator, /Producer, /CreationDate, /ModDate, /Title) was completely removed.",
            "Document Catalog XMP Metadata stream (/Metadata) was removed.",
            "Page contents, vector paths, text objects, and fonts were preserved."
        ]
        if warnings:
            notes.extend(warnings)

        return {
            "success": True,
            "method": "PDF catalog and Info dictionary sanitization via clean stream re-writing",
            "notes": notes,
            "unsupported_structures": unsupported_structures
        }
    except Exception as exc:
        raise CleaningError(f"PDF cleaning failed: {exc}")


def clean_file(
    input_path: str,
    file_type: str,
    cleaned_dir: str
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Dispatches cleaning to the appropriate format cleaner.
    Guarantees original file is never overwritten.
    Returns (cleaned_filename, cleaned_full_path, cleaning_details).
    """
    os.makedirs(cleaned_dir, exist_ok=True)
    extension = ".jpg" if file_type.upper() == "JPEG" else ".pdf"
    cleaned_filename = f"clean_{uuid.uuid4().hex}{extension}"
    cleaned_full_path = os.path.abspath(os.path.join(cleaned_dir, cleaned_filename))

    if file_type.upper() == "JPEG":
        details = clean_jpeg(input_path, cleaned_full_path)
    elif file_type.upper() == "PDF":
        details = clean_pdf(input_path, cleaned_full_path)
    else:
        raise CleaningError(f"Unsupported file type for cleaning: {file_type}")

    return cleaned_filename, cleaned_full_path, details
