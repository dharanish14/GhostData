"""
Tests for GhostData Flask API, Endpoints, and Security Measures
"""

import os
import io
import json


def test_index_route(test_client):
    res = test_client.get("/")
    assert res.status_code == 200
    assert b"GhostData" in res.data
    assert b"Privacy Risk Analyzer" in res.data


def test_upload_rejects_missing_csrf(test_client, sample_dir):
    gps_file = os.path.join(sample_dir, "sample_with_gps.jpg")
    with open(gps_file, "rb") as f:
        data = {"file": (io.BytesIO(f.read()), "test.jpg")}
        # Omitting X-CSRF-Token
        res = test_client.post("/api/upload", data=data, content_type="multipart/form-data")
        assert res.status_code == 403
        json_data = res.get_json()
        assert json_data["code"] == "CSRF_ERROR"


def test_upload_and_clean_workflow(test_client, sample_dir):
    gps_file = os.path.join(sample_dir, "sample_with_gps.jpg")
    csrf_token = "test-csrf-token-abc"

    # 1. Upload valid JPEG with GPS
    with open(gps_file, "rb") as f:
        data = {"file": (io.BytesIO(f.read()), "sample_with_gps.jpg")}
        res = test_client.post(
            "/api/upload",
            data=data,
            headers={"X-CSRF-Token": csrf_token},
            content_type="multipart/form-data"
        )
        assert res.status_code == 200
        upload_res = res.get_json()
        file_id = upload_res["file_id"]
        assert upload_res["file_type"] == "JPEG"
        assert upload_res["risk_report"]["overall_risk"] == "HIGH"

    # 2. Clean and Verify
    clean_payload = json.dumps({"file_id": file_id})
    res_clean = test_client.post(
        "/api/clean",
        data=clean_payload,
        headers={"X-CSRF-Token": csrf_token, "Content-Type": "application/json"}
    )
    assert res_clean.status_code == 200
    clean_res = res_clean.get_json()
    assert clean_res["success"] is True
    assert clean_res["verification"]["is_verified_clean"] is True

    # 3. Download Cleaned File
    res_dl = test_client.get(f"/download/{file_id}")
    assert res_dl.status_code == 200
    assert res_dl.mimetype == "image/jpeg"
    assert "attachment" in res_dl.headers.get("Content-Disposition", "")

    # 4. Standalone Report View
    res_rep = test_client.get(f"/report/{file_id}")
    assert res_rep.status_code == 200
    assert b"GhostData Privacy Audit" in res_rep.data


def test_cross_session_download_isolation(test_client, sample_dir):
    # Upload with current session
    clean_pdf = os.path.join(sample_dir, "sample_clean.pdf")
    csrf_token = "test-csrf-token-abc"

    with open(clean_pdf, "rb") as f:
        data = {"file": (io.BytesIO(f.read()), "sample_clean.pdf")}
        res = test_client.post(
            "/api/upload",
            data=data,
            headers={"X-CSRF-Token": csrf_token},
            content_type="multipart/form-data"
        )
        file_id = res.get_json()["file_id"]

    # Trigger clean
    test_client.post(
        "/api/clean",
        data=json.dumps({"file_id": file_id}),
        headers={"X-CSRF-Token": csrf_token, "Content-Type": "application/json"}
    )

    # Now change session ID to simulate an attacker trying to access another user's download
    with test_client.session_transaction() as sess:
        sess["session_id"] = "attacker-unauthorized-session-999"

    res_forbidden = test_client.get(f"/download/{file_id}")
    assert res_forbidden.status_code == 403
