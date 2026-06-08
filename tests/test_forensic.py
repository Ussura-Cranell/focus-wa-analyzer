import pytest
import json
import os
from pathlib import Path
from freezegun import freeze_time
from core.pipeline import run_scan
from sources.local_dir import LocalDirSource
from core.models import ScanManifest
import shutil

FIXTURES = Path(__file__).parent / "test_assets"
GOLDEN = Path(__file__).parent / "golden"

@pytest.fixture(autouse=True)
def freeze_ts():
    with freeze_time("2024-05-12T14:30:00Z"):
        yield

def create_test_assets():
    FIXTURES.mkdir(exist_ok=True)
    # Minimal valid JPEG
    jpeg_data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9'
    (FIXTURES / "sample.jpg").write_bytes(jpeg_data)
    # Spoofed EXE
    exe_data = b'MZ' + b'\x00' * 50 + b'\xff\xd9'
    (FIXTURES / "spoofed.jpg").write_bytes(exe_data)
    # Tampered
    (FIXTURES / "tampered.jpg").write_bytes(jpeg_data + b'\x01')

@pytest.fixture(scope="module", autouse=True)
def setup():
    create_test_assets()
    yield

def test_baseline_generation():
    source = LocalDirSource()
    manifest = run_scan(source, FIXTURES)
    assert len(manifest.files) >= 3
    assert all(rec.hash_content for rec in manifest.files.values())
    
    out = GOLDEN / "baseline_test.json"
    data = {k: v.__dict__ for k, v in manifest.files.items()}
    out.write_text(json.dumps(data, sort_keys=True, indent=2))
    print(f"[+] Golden baseline saved: {out}")

def test_spoof_detection():
    from core.profiler import profile_file
    res = profile_file(FIXTURES / "spoofed.jpg", strict=True)
    assert res["match_status"] == "MISMATCH"

def test_content_tamper():
    h1 = run_scan(LocalDirSource(), FIXTURES).files["sample.jpg"].hash_content
    h2 = run_scan(LocalDirSource(), FIXTURES).files["tampered.jpg"].hash_content
    assert h1 != h2

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

class TestForensicControlledAssets:
    """Тесты на реальных, контролируемых форензик-ассетах."""

    def test_photoshop_detection(self):
        filepath = Path("tests/test_assets/forensic_controlled/photoshopped.jpg")
        if not filepath.exists():
            pytest.skip("Controlled asset not found")
        from core.extractor import extract_file
        rec = extract_file(filepath, filepath.parent.parent)
        # exifread называет тег "Image Software" (IFD0), а не "EXIF Software"
        assert rec.metadata.get("Image Software") == "Adobe Photoshop 2024"

    def test_stripped_metadata_handling(self):
        filepath = Path("tests/test_assets/forensic_controlled/stripped.jpg")
        if not filepath.exists():
            pytest.skip("Controlled asset not found")
        from core.extractor import extract_file
        rec = extract_file(filepath, filepath.parent.parent)
        # После exiftool -all= критических EXIF-тегов быть не должно
        assert "EXIF DateTimeOriginal" not in rec.metadata
        assert "GPS GPSLatitude" not in rec.metadata
        # metadata может быть пустым или содержать только базовые теги
        assert isinstance(rec.metadata, dict)

    def test_temporal_anomaly_detection(self):
        filepath = Path("tests/test_assets/forensic_controlled/time_travel.jpg")
        if not filepath.exists():
            pytest.skip("Controlled asset not found")
        from core.extractor import extract_file
        rec = extract_file(filepath, filepath.parent.parent)
        date_str = rec.metadata.get("EXIF DateTimeOriginal", "")
        assert "2035" in date_str  # Проверка, что аномальная дата извлечена корректно

    def test_office_revision_extraction(self):
        filepath = Path("tests/test_assets/forensic_controlled/office_revision.docx")
        if not filepath.exists():
            pytest.skip("Controlled asset not found")
        from core.extractor import extract_file
        rec = extract_file(filepath, filepath.parent.parent)
        assert "Office Author" in rec.metadata
        assert "Office Revision" in rec.metadata