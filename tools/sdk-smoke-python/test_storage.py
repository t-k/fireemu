"""firebase_admin.storage (google-cloud-storage, GCS JSON API) against fireemu."""

import pytest
from firebase_admin import storage
from google.api_core.exceptions import NotFound


def test_upload_download_metadata_delete(app, unique):
    bucket = storage.bucket(app=app)
    blob = bucket.blob(f"py-smoke/{unique}.txt")
    blob.upload_from_string(b"hello from python", content_type="text/plain")
    assert bucket.blob(f"py-smoke/{unique}.txt").download_as_bytes() == b"hello from python"
    fetched = bucket.get_blob(f"py-smoke/{unique}.txt")
    assert fetched is not None
    assert fetched.size == len(b"hello from python")
    assert fetched.content_type == "text/plain"
    assert fetched.md5_hash
    fetched.delete()
    assert bucket.get_blob(f"py-smoke/{unique}.txt") is None
    with pytest.raises(NotFound):
        bucket.blob(f"py-smoke/{unique}.txt").download_as_bytes()
