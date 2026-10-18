"""
GhostData Test Suite Fixtures and Configuration
"""

import os
import shutil
import pytest
from app import app, STORAGE_DIR, UPLOAD_DIR, CLEAN_DIR, FILE_REGISTRY
from sample_files.generate_samples import generate_all_samples


@pytest.fixture(scope="session")
def sample_dir(tmp_path_factory):
    temp_dir = str(tmp_path_factory.mktemp("synthetic_samples"))
    generate_all_samples(temp_dir)
    return temp_dir


@pytest.fixture
def test_client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-for-ghostdata"
    FILE_REGISTRY.clear()
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["session_id"] = "test-session-12345"
            sess["csrf_token"] = "test-csrf-token-abc"
        yield client


@pytest.fixture
def isolated_storage(tmp_path):
    uploads = tmp_path / "uploads"
    cleaned = tmp_path / "cleaned"
    uploads.mkdir(parents=True, exist_ok=True)
    cleaned.mkdir(parents=True, exist_ok=True)
    return str(uploads), str(cleaned)
