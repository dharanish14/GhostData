"""
GhostData - Synthetic Sample Generator
Generates clean and metadata-rich synthetic sample test files (JPEG and PDF)
without using any real-world or personal data.
"""

import os
from PIL import Image, ImageDraw
import piexif
from pypdf import PdfWriter


def generate_all_samples(target_dir: str):
    os.makedirs(target_dir, exist_ok=True)

    # 1. Synthetic JPEG with GPS and Camera metadata
    gps_jpg_path = os.path.join(target_dir, "sample_with_gps.jpg")
    img = Image.new("RGB", (400, 300), color=(30, 60, 90))
    draw = ImageDraw.Draw(img)
    draw.rectangle([20, 20, 380, 280], outline=(200, 200, 200), width=3)

    zeroth_ifd = {
        piexif.ImageIFD.Make: "GhostCamera Corp",
        piexif.ImageIFD.Model: "PrivacyCheck 9000",
        piexif.ImageIFD.Software: "GhostData Synthetic Gen v1.0",
        piexif.ImageIFD.Artist: "Jane Doe (jane.doe@example.org)",
        piexif.ImageIFD.DateTime: "2024:06:15 14:30:00",
    }
    exif_ifd = {
        piexif.ExifIFD.DateTimeOriginal: "2024:06:15 14:30:00",
        piexif.ExifIFD.LensModel: "GhostLens 50mm f/1.8",
        piexif.ExifIFD.BodySerialNumber: "SN-9876543210",
        piexif.ExifIFD.UserComment: b"Synthetic Test Image Generated For Privacy Audit",
    }
    # 37.77492° N, 122.41941° W (San Francisco Civic Center)
    gps_ifd = {
        piexif.GPSIFD.GPSLatitudeRef: "N",
        piexif.GPSIFD.GPSLatitude: ((37, 1), (46, 1), (2971, 100)),
        piexif.GPSIFD.GPSLongitudeRef: "W",
        piexif.GPSIFD.GPSLongitude: ((122, 1), (25, 1), (988, 100)),
        piexif.GPSIFD.GPSAltitudeRef: 0,
        piexif.GPSIFD.GPSAltitude: (45, 1),
        piexif.GPSIFD.GPSDateStamp: "2024:06:15",
        piexif.GPSIFD.GPSTimeStamp: ((14, 1), (30, 1), (0, 1)),
    }
    exif_dict = {"0th": zeroth_ifd, "Exif": exif_ifd, "GPS": gps_ifd}
    exif_bytes = piexif.dump(exif_dict)
    img.save(gps_jpg_path, "JPEG", exif=exif_bytes)

    # 2. Synthetic JPEG without metadata
    clean_jpg_path = os.path.join(target_dir, "sample_clean.jpg")
    img_clean = Image.new("RGB", (400, 300), color=(40, 120, 60))
    img_clean.save(clean_jpg_path, "JPEG")

    # 3. Synthetic PDF with Author and Timestamps
    meta_pdf_path = os.path.join(target_dir, "sample_with_metadata.pdf")
    writer = PdfWriter()
    page = writer.add_blank_page(width=400, height=300)
    writer.add_metadata({
        "/Author": "Dr. Alice Smith (alice.smith@example.org)",
        "/Creator": "GhostData PDF Generator",
        "/Producer": "Internal Enterprise Publishing Suite v4.2",
        "/Title": "Internal Project Falcon Architecture",
        "/Subject": "Confidential Technical Specification",
        "/Keywords": "internal, architecture, classified",
        "/CreationDate": "D:20240615143000+00'00'",
        "/ModDate": "D:20240615150000+00'00'",
    })
    with open(meta_pdf_path, "wb") as f:
        writer.write(f)

    # 4. Synthetic Clean PDF without metadata
    clean_pdf_path = os.path.join(target_dir, "sample_clean.pdf")
    writer_clean = PdfWriter()
    writer_clean.add_blank_page(width=400, height=300)
    writer_clean._info = None
    with open(clean_pdf_path, "wb") as f:
        writer_clean.write(f)

    print(f"[+] Successfully generated synthetic sample files in: {target_dir}")
    print(f"  - {gps_jpg_path} (JPEG with GPS and Camera tags)")
    print(f"  - {clean_jpg_path} (JPEG with zero EXIF)")
    print(f"  - {meta_pdf_path} (PDF with Author, Creator, Title)")
    print(f"  - {clean_pdf_path} (PDF with zero metadata)")


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    generate_all_samples(current_dir)
