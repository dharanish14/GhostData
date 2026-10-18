# GhostData Synthetic Sample Files

This directory contains synthetic test files specifically crafted for privacy risk analysis and metadata sanitization testing.

## Ethical & Privacy Guarantee
None of these test files contain real-world personal data, real GPS locations of private properties, or live user identities. All coordinates, emails, and device names are synthetic mock values created for security testing and demonstration.

## Files Description

1. **`sample_with_gps.jpg`**:
   - Format: JPEG
   - Synthetic EXIF metadata:
     - Make: `GhostCamera Corp`
     - Model: `PrivacyCheck 9000`
     - Lens: `GhostLens 50mm f/1.8`
     - Serial: `SN-9876543210`
     - Artist: `Jane Doe (jane.doe@example.org)`
     - GPS: Latitude `37.77492° N`, Longitude `122.41941° W`, Altitude `45m`
     - Timestamp: `2024:06:15 14:30:00`
   - Purpose: Demonstrates high-risk geolocation and device fingerprinting detection.

2. **`sample_clean.jpg`**:
   - Format: JPEG
   - Metadata: Zero EXIF/IPTC/XMP headers.
   - Purpose: Demonstrates minimal risk baseline analysis.

3. **`sample_with_metadata.pdf`**:
   - Format: PDF
   - Document Information Dictionary:
     - Author: `Dr. Alice Smith (alice.smith@example.org)`
     - Creator: `GhostData PDF Generator`
     - Producer: `Internal Enterprise Publishing Suite v4.2`
     - Title: `Internal Project Falcon Architecture`
     - Subject: `Confidential Technical Specification`
     - Creation Date: `2024-06-15`
   - Purpose: Demonstrates corporate document metadata detection.

4. **`sample_clean.pdf`**:
   - Format: PDF
   - Metadata: Clean structure with empty metadata catalog.
   - Purpose: Baseline clean document verification.

## Regrowth / Re-generation
To re-generate all sample files at any time, run:
```bash
python sample_files/generate_samples.py
```
