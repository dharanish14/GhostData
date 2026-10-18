# 🛡️ GhostData — Privacy Risk Analyzer & Verified Metadata Sanitizer

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Security Architecture](https://img.shields.io/badge/security-local--first-green.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)
![Tests](https://img.shields.io/badge/tests-27%2F27%20passing-brightgreen.svg)

**GhostData** is a local-first cybersecurity web application that inspects JPEG images and PDF documents for hidden metadata, explains the privacy implications of detected items using plain-English security rubrics, and creates a verified, sanitized copy when requested.

---

## 📌 Table of Contents

- [Why GhostData Matters](#-why-ghostdata-matters)
- [Architecture & Data Flow](#-architecture--data-flow)
- [Core Features](#-core-features)
- [Security & Threat Model](#-security--threat-model)
- [Prerequisites & Installation](#-prerequisites--installation)
  - [Option A: Windows PowerShell](#option-a-windows-powershell)
  - [Option B: WSL (Ubuntu)](#option-b-wsl-ubuntu)
- [Running the Application](#-running-the-application)
- [Generating Synthetic Test Data](#-generating-synthetic-test-data)
- [Running Automated Tests](#-running-automated-tests)
- [Evidence-Based Verification Engine](#-evidence-based-verification-engine)
- [Limitations & Threat Disclosures](#-limitations--threat-disclosures)
- [Project Structure](#-project-structure)

---

## 🔍 Why GhostData Matters

When you take a photo with a smartphone or generate an office document, software silently embeds hidden container headers:
- **JPEG EXIF**: GPS latitude/longitude, altitude, exact capture timestamps, camera make/model, serial numbers, and software names.
- **PDF Catalog / Info**: Author real name, organization, workstation usernames, internal project titles, creation/modification dates, and creator tools.

Sharing these files without sanitization exposes private residences, travel routines, internal corporate networks, and organizational identities.

**GhostData** bridges this gap: it extracts hidden data, translates raw byte structures into transparent privacy ratings, strips metadata safely without damaging visual orientation or document layout, and **re-scans the output file to mathematically verify sanitization**.

---

## 🏗️ Architecture & Data Flow

```
[Untrusted File]
       │
       ▼
[1. Signature & Magic Byte Validator]
  ├── Validates b'\xff\xd8\xff' (JPEG) or b'%PDF-' (PDF)
  ├── Enforces 10 MB upload threshold
  └── Assigns UUIDv4 filename (Never uses client filename)
       │
       ▼
[2. Metadata Extraction Layer]
  ├── image_metadata.py (EXIF, GPS DMS->Decimal, Camera Serials)
  └── pdf_metadata.py (Info Dict, Dates, XMP streams, Annotations)
       │
       ▼
[3. Rule-Based Privacy Risk Engine]
  ├── Evaluates findings: HIGH / MEDIUM / LOW / INFO
  ├── Masks sensitive coordinates & identities
  └── Generates plain-English concern & suggested action
       │
       ▼
[4. Sanitization & Re-encoding Engine]
  ├── JPEG: ImageOps.exif_transpose + Re-encode without EXIF chunks
  └── PDF: Omit /Info dictionary & scrub catalog /Metadata stream
       │
       ▼
[5. Post-Cleaning Verification Engine]
  ├── Re-extracts metadata from sanitized file
  ├── Performs field-by-field diff (Removed vs. Remaining)
  └── Confirms structural integrity & format readability
       │
       ▼
[Verified Clean Copy & Audit Report]
```

---

## ✨ Core Features

1. **Signature-Based Inspection**: Validates genuine file signatures (magic bytes) rather than trusting spoofable MIME types or file extensions.
2. **Precision GPS & Hardware Extraction**: Converts Degree/Minute/Second EXIF coordinates to decimal degrees, extracts altitude, satellite time, and camera body serial numbers.
3. **Transparent Privacy Rubric**:
   - **HIGH**: Exact physical location (GPS), hardware serial numbers, raw email addresses.
   - **MEDIUM**: Document author names, internal project titles, interactive PDF annotations.
   - **LOW**: Device make/model, software generators, timestamps (routine footprint).
   - **INFO**: Image dimensions, color space, page count.
4. **Orientation-Safe JPEG Sanitization**: Uses `ImageOps.exif_transpose()` to permanently bake physical orientation into pixel matrices before dropping EXIF tags, preventing rotated images.
5. **PDF Deep Header Scrubbing**: Strips Document Information Dictionaries and XMP catalog streams while preserving page layouts, fonts, and vector paths.
6. **Evidence-Based Verification**: Runs second-pass extraction on the sanitized file. Never reports success based solely on a function call completing without error.
7. **Session Isolation & CSRF Protection**: Uploads and downloads are bound to unique cryptographic session tokens. Users cannot access other users' files.
8. **Printable Standalone Audit Reports**: View or print full before-and-after audit logs.

---

## 🔒 Security & Threat Model

| Threat | Risk | GhostData Countermeasure |
| :--- | :--- | :--- |
| **Path Traversal (`../../evil.jpg`)** | Arbitrary file write / overwrite | Client filenames are stripped. Storage uses strictly server-generated `uuid.uuid4().hex`. |
| **Extension Spoofing (`exploit.exe` -> `file.jpg`)** | Code execution / Parser exploits | Files are validated by inspecting true binary magic bytes (`\xff\xd8\xff` / `%PDF-`) followed by strict parser validation. |
| **Denial of Service (Zip bombs, large files)** | Resource exhaustion | 10 MB strict streaming cap enforced at both web-server and chunked-reader levels. |
| **Cross-User Data Leakage** | Unauthorized file access | In-memory registry maps `file_id` to cryptographic `session_id`. Unauthorized requests return HTTP 403. |
| **CSRF File Injection** | Forced malicious upload | Cryptographic `csrf_token` issued in user session and validated on all POST endpoints. |
| **Disk Exhaustion** | Storage accumulation | Automatic timestamp-based expiration purges files older than 1 hour. |

---

## 💻 Prerequisites & Installation

GhostData requires **Python 3.10+** (Python 3.11+ recommended).

### Option A: Windows PowerShell

1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd d:\projects\GhostData
   ```

2. Create and activate a Python virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   *(If script execution is restricted, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

3. Install required dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

---

### Option B: WSL (Ubuntu)

1. Open your WSL Ubuntu terminal and navigate to the Windows project path:
   ```bash
   cd /mnt/d/projects/GhostData
   ```

2. Ensure Python 3 and venv are installed:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-venv python3-pip
   ```

3. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Running the Application

1. Start the Flask application:
   ```bash
   # Windows PowerShell
   .\.venv\Scripts\python app.py

   # WSL Ubuntu
   python3 app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

3. Drag & drop a JPEG photo or PDF document to view live privacy risk analysis, or use the synthetic test files in `sample_files/`.

---

## 🧪 Generating Synthetic Test Data

To guarantee ethical testing without exposing real personal photographs or confidential files, GhostData includes a synthetic sample generator:

```bash
python sample_files/generate_samples.py
```

This generates:
- `sample_files/sample_with_gps.jpg`: Synthetic JPEG with GPS coordinates (San Francisco Civic Center), camera make/model, lens, and serial tags.
- `sample_files/sample_clean.jpg`: Baseline JPEG with zero EXIF tags.
- `sample_files/sample_with_metadata.pdf`: Synthetic PDF with author identity, creator software, internal project title, and creation timestamp.
- `sample_files/sample_clean.pdf`: Baseline PDF with zero metadata.

---

## 🔬 Running Automated Tests

Run the comprehensive 27-test suite using `pytest`:

```bash
# Windows PowerShell
.\.venv\Scripts\pytest -v

# WSL Ubuntu
pytest -v
```

### Expected Output:
```text
============================= test session starts =============================
platform win32 -- Python 3.11.3, pytest-9.1.1
collected 27 items

tests/test_app.py::test_index_route PASSED                               [  3%]
tests/test_app.py::test_upload_rejects_missing_csrf PASSED               [  7%]
tests/test_app.py::test_upload_and_clean_workflow PASSED                 [ 11%]
tests/test_app.py::test_cross_session_download_isolation PASSED          [ 14%]
tests/test_cleaner.py::test_clean_jpeg_preserves_original_and_strips_metadata PASSED [ 18%]
tests/test_cleaner.py::test_clean_pdf_preserves_original_and_strips_metadata PASSED [ 22%]
tests/test_image_metadata.py::test_dms_conversion PASSED                 [ 25%]
tests/test_image_metadata.py::test_extract_jpeg_with_gps PASSED          [ 29%]
tests/test_image_metadata.py::test_extract_clean_jpeg PASSED             [ 33%]
tests/test_pdf_metadata.py::test_pdf_date_parsing PASSED                 [ 37%]
tests/test_pdf_metadata.py::test_extract_pdf_with_metadata PASSED        [ 40%]
tests/test_pdf_metadata.py::test_extract_clean_pdf PASSED                [ 44%]
tests/test_risk_engine.py::test_coordinate_masking PASSED                [ 48%]
tests/test_risk_engine.py::test_string_masking PASSED                    [ 51%]
tests/test_risk_engine.py::test_risk_analysis_with_gps PASSED            [ 55%]
tests/test_risk_engine.py::test_risk_analysis_clean_file PASSED          [ 59%]
tests/test_validators.py::test_detect_jpeg_magic_bytes PASSED            [ 62%]
tests/test_validators.py::test_detect_pdf_magic_bytes PASSED             [ 66%]
tests/test_validators.py::test_reject_unsupported_magic_bytes PASSED     [ 70%]
tests/test_validators.py::test_secure_storage_path_never_uses_original_name PASSED [ 74%]
tests/test_validators.py::test_reject_empty_file PASSED                  [ 77%]
tests/test_validators.py::test_reject_extension_spoofing PASSED          [ 81%]
tests/test_validators.py::test_reject_oversized_file PASSED              [ 85%]
tests/test_validators.py::test_reject_corrupt_jpeg PASSED                [ 88%]
tests/test_validators.py::test_reject_corrupt_pdf PASSED                 [ 92%]
tests/test_verifier.py::test_verify_file_validity PASSED                 [ 96%]
tests/test_verifier.py::test_full_cleaning_and_verification_pipeline PASSED [100%]

============================= 27 passed in 0.51s ==============================
```

---

## 📊 Evidence-Based Verification Engine

Unlike tools that display a "Cleaned Successfully" notification merely because a script ran without crashing, GhostData enforces an evidence-based verification rule:

1. **Readability Check**: Opens the cleaned output using official parsers (`PIL.Image.open` and `pypdf.PdfReader`) to confirm the file is not corrupted or truncated.
2. **Second-Pass Inspection**: Re-executes the exact same metadata extraction engine on the newly created file.
3. **Diff Calculation**:
   - **Targeted Removed Fields**: Fields found in original file but absent in cleaned file.
   - **Remaining Fields**: Any targeted metadata still present.
   - **Preserved / Unverified Structures**: Elements like PDF `/Annots` (annotations) or `/EmbeddedFiles` that cannot be scrubbed without risking document destruction.
4. **Verdict Decision**: An output is only declared `VERIFIED_CLEAN` if all high/medium risk items are confirmed absent and file integrity is intact.

---

## ⚠️ Limitations & Threat Disclosures

In accordance with cybersecurity engineering standards:

1. **Visible Content Disclosure**: Metadata cleaning strips file headers, but **does not redact text, face photographs, street signs, house numbers, or screenshots printed directly in the visual content**.
2. **Deep PDF Structures**: PDF files may contain incremental revisions, object streams, interactive JavaScript, and annotations. GhostData scrubs standard document information and catalog XMP streams, but flags embedded files and annotations for manual user review.
3. **Local Application Security**: Processing files locally prevents third-party data interception, but local machines must be kept secure against malware with filesystem access.

---

## 📂 Project Structure

```
GhostData/
├── app.py                     # Flask web server, secure routes, session isolation
├── requirements.txt           # Verified dependencies (Flask, Pillow, pypdf, piexif, pytest)
├── README.md                  # Complete documentation and portfolio guide
├── .gitignore                 # Excludes caches, venvs, and temporary user storage
├── analyzer/
│   ├── __init__.py            # Package interface
│   ├── validators.py          # Magic byte inspection, 10MB limits, UUID filenames
│   ├── image_metadata.py      # JPEG EXIF & GPS DMS->Decimal converter
│   ├── pdf_metadata.py        # PDF DocInfo, XMP streams, structural check
│   ├── risk_engine.py         # Rule-based privacy scoring and masking engine
│   ├── cleaner.py             # Metadata stripping (Orientation-safe JPEG & PDF re-write)
│   └── verifier.py            # Second-pass inspection and evidence-based diffing
├── templates/
│   ├── index.html             # Main dashboard UI
│   └── report.html            # Standalone printable audit report
├── static/
│   ├── style.css              # Dark-mode cybersecurity styling
│   └── app.js                 # Drag-and-drop, AJAX upload, live UI updates
├── sample_files/
│   ├── generate_samples.py    # Synthetic test file generator
│   └── README.md              # Ethical test file documentation
├── storage/
│   ├── uploads/               # Temporary isolated uploads (excluded from Git)
│   └── cleaned/               # Generated clean copies (excluded from Git)
└── tests/
    ├── conftest.py            # Pytest test fixtures and isolated storage setup
    ├── test_validators.py     # Signature and security boundary tests
    ├── test_image_metadata.py # JPEG extraction and GPS tests
    ├── test_pdf_metadata.py   # PDF extraction and date parsing tests
    ├── test_risk_engine.py    # Risk scoring and coordinate masking tests
    ├── test_cleaner.py        # Sanitization tests
    ├── test_verifier.py       # Verification diff tests
    └── test_app.py            # Full API integration and cross-session isolation tests
```
