# tests/test_analyzers.py
"""Тесты для анализаторов baseline и compare."""
import pytest
from core.reporting.analyzers.baseline import BaselineAnalyzer
from core.reporting.analyzers.compare import CompareAnalyzer


def _file(**overrides):
    """Базовый файл-затычка."""
    base = {
        "relative_path": "test.jpg",
        "size_bytes": 1000,
        "declared_ext": ".jpg",
        "real_mime": "image/jpeg",
        "match_status": "MATCH",
        "is_media": True,
        "is_document": False,
        "metadata": {},
        "hash_content": "abc123",
    }
    base.update(overrides)
    return base


class TestBaselineAnalyzer:
    def test_summary_counts(self):
        files = {
            "a.jpg": _file(is_media=True, is_document=False),
            "b.pdf": _file(relative_path="b.pdf", declared_ext=".pdf",
                           real_mime="application/pdf",
                           is_media=False, is_document=True),
        }
        result = BaselineAnalyzer(files).analyze()
        assert result["summary"]["total_files"] == 2
        assert result["summary"]["media_files"] == 1
        assert result["summary"]["document_files"] == 1

    def test_temporal_distribution(self):
        files = {
            "a.jpg": _file(metadata={"EXIF DateTimeOriginal": "2023-05-15T10:00:00"}),
            "b.jpg": _file(relative_path="b.jpg",
                           metadata={"EXIF DateTimeOriginal": "2023-06-20T10:00:00"}),
            "c.jpg": _file(relative_path="c.jpg", metadata={}),
        }
        result = BaselineAnalyzer(files).analyze()
        assert result["temporal_distribution"]["by_year"]["2023"] == 2
        assert result["temporal_distribution"]["undated"] == 1

    def test_future_date_anomaly(self):
        files = {"a.jpg": _file(metadata={"EXIF DateTimeOriginal": "2035-01-01T12:00:00"})}
        result = BaselineAnalyzer(files).analyze()
        assert len(result["temporal_distribution"]["anomalies"]) == 1
        assert result["temporal_distribution"]["anomalies"][0]["reason"] == "future_date"

    def test_gps_coverage(self):
        files = {
            "a.jpg": _file(metadata={"GPS GPSLatitude": "[55, 45]", "GPS GPSLongitude": "[37, 37]"}),
            "b.jpg": _file(relative_path="b.jpg", metadata={}),
        }
        result = BaselineAnalyzer(files).analyze()
        assert result["gps_coverage"]["files_with_gps"] == 1
        assert result["gps_coverage"]["coverage_percent"] == 50.0

    def test_software_chain(self):
        files = {
            "a.jpg": _file(metadata={"Image Software": "Adobe Photoshop 2024"}),
            "b.jpg": _file(relative_path="b.jpg",
                           metadata={"Image Software": "Adobe Photoshop 2024"}),
            "c.jpg": _file(relative_path="c.jpg",
                           metadata={"Image Software": "GIMP 2.10"}),
        }
        result = BaselineAnalyzer(files).analyze()
        assert result["software_chain"]["Adobe Photoshop 2024"] == 2
        assert result["software_chain"]["GIMP 2.10"] == 1

    def test_critical_finding_mime_mismatch(self):
        files = {"a.jpg": _file(match_status="MISMATCH", real_mime="application/x-msdownload")}
        result = BaselineAnalyzer(files).analyze()
        assert len(result["critical_findings"]) == 1
        assert result["critical_findings"][0]["type"] == "mime_mismatch"
        assert result["critical_findings"][0]["severity"] == "HIGH"

    def test_critical_finding_photoshop(self):
        files = {"a.jpg": _file(metadata={"Image Software": "Adobe Photoshop 2024"})}
        result = BaselineAnalyzer(files).analyze()
        types = [f["type"] for f in result["critical_findings"]]
        assert "edited_by_software" in types


class TestCompareAnalyzer:
    def test_summary_counts(self):
        old = {"a.jpg": _file(hash_content="aaa")}
        new = {"a.jpg": _file(hash_content="bbb"),
               "b.jpg": _file(relative_path="b.jpg", hash_content="ccc")}
        diff = [
            {"status": "CONTENT_MODIFIED", "path": "a.jpg", "details": {"old_hash": "aaa", "new_hash": "bbb", "size_delta": 10}},
            {"status": "ADDED", "path": "b.jpg", "details": {"hash": "ccc"}},
        ]
        result = CompareAnalyzer(old, new, diff).analyze()
        assert result["summary"]["content_modified"] == 1
        assert result["summary"]["added"] == 1

    def test_deletion_with_gps_is_critical(self):
        old = {"a.jpg": _file(metadata={"GPS GPSLatitude": "[55]", "GPS GPSLongitude": "[37]"})}
        new = {}
        diff = [{"status": "DELETED", "path": "a.jpg",
                 "details": {"old_hash": "xyz"}}]
        result = CompareAnalyzer(old, new, diff).analyze()
        assert result["deletions"]["with_gps_count"] == 1
        findings = result["critical_findings"]
        assert any(f["type"] == "gps_evidence_deleted" for f in findings)

    def test_mass_deletion_detection(self):
        old = {f"f{i}.jpg": _file(relative_path=f"f{i}.jpg") for i in range(15)}
        new = {}
        diff = [{"status": "DELETED", "path": p, "details": {"old_hash": "x"}} for p in old]
        result = CompareAnalyzer(old, new, diff).analyze()
        assert any(f["type"] == "mass_deletion" for f in result["critical_findings"])

    def test_move_detection(self):
        old = {"dir1/a.jpg": _file(relative_path="dir1/a.jpg", hash_content="same")}
        new = {"dir2/a.jpg": _file(relative_path="dir2/a.jpg", hash_content="same")}
        diff = [{"status": "MOVED", "path": "dir2/a.jpg",
                 "details": {"from": "dir1/a.jpg", "to": "dir2/a.jpg"}}]
        result = CompareAnalyzer(old, new, diff).analyze()
        assert result["moves"]["count"] == 1
        assert result["moves"]["cross_directory_moves"] == 1

    def test_datetime_tampering_detection(self):
        old = {"a.jpg": _file(metadata={"EXIF DateTimeOriginal": "2023-05-15T10:00:00"})}
        new = {"a.jpg": _file(metadata={"EXIF DateTimeOriginal": "2020-01-01T10:00:00"})}
        diff = [{"status": "META_MODIFIED", "path": "a.jpg", "details": {}}]
        result = CompareAnalyzer(old, new, diff).analyze()
        assert any(f["type"] == "datetime_tampering" for f in result["critical_findings"])

    def test_metadata_top_changed_fields(self):
        old = {"a.jpg": _file(metadata={"EXIF DateTimeOriginal": "2023", "GPS GPSLatitude": "55"})}
        new = {"a.jpg": _file(metadata={"EXIF DateTimeOriginal": "2024", "GPS GPSLatitude": "56"})}
        diff = [{"status": "META_MODIFIED", "path": "a.jpg", "details": {}}]
        result = CompareAnalyzer(old, new, diff).analyze()
        fields = result["metadata_modifications"]["top_changed_fields"]
        assert "EXIF DateTimeOriginal" in fields
        assert "GPS GPSLatitude" in fields