"""Тесты для JsonStorage и SQLiteStorage"""
import json
import pytest
import tempfile
from pathlib import Path
from dataclasses import asdict
from core.storage import JsonStorage, SQLiteStorage
from core.models import ScanManifest, FileRecord
from datetime import datetime, timezone
import config


def _make_manifest(name: str = "test", files_count: int = 2) -> ScanManifest:
    """Вспомогательная функция: создаёт тестовый манифест"""
    files = {}
    for i in range(files_count):
        path = f"folder/file_{i}.jpg"
        files[path] = FileRecord(
            relative_path=path,
            absolute_path=f"/tmp/{path}",
            size_bytes=1000 + i,
            hash_content=f"content_hash_{i}",
            hash_meta=f"meta_hash_{i}",
            declared_ext=".jpg",
            real_mime="image/jpeg",
            match_status="MATCH",
            is_media=True,
            is_document=False,
            metadata={"EXIF DateTimeOriginal": f"2025-01-0{i+1}T00:00:00+00:00"},
            scan_timestamp="2026-06-02T10:00:00+00:00",
        )
    return ScanManifest(
        scan_id=f"scan_{name}",
        source_root="/tmp/test_assets",
        scan_timestamp="2026-06-02T10:00:00+00:00",
        files=files,
        warnings=["test warning"],
    )


# =================== JsonStorage ===================

class TestJsonStorage:
    def test_save_and_load(self, tmp_path):
        path = tmp_path / "scan.json"
        storage = JsonStorage(path)
        manifest = _make_manifest()
        storage.save_manifest(manifest, "test_name", notes="hello")

        loaded = storage.load_manifest(str(path))
        assert len(loaded.files) == 2
        assert loaded.scan_id == manifest.scan_id
        assert "folder/file_0.jpg" in loaded.files

    def test_save_with_signature(self, tmp_path):
        path = tmp_path / "scan.json"
        storage = JsonStorage(path)
        manifest = _make_manifest()
        sig = config.sign_report(asdict(manifest))
        storage.save_manifest(manifest, "test", signature=sig)

        with open(path) as f:
            data = json.load(f)
        assert data["_signature"] == sig

    def test_list_scans_empty(self, tmp_path):
        path = tmp_path / "missing.json"
        storage = JsonStorage(path)
        assert storage.list_scans() == []

    def test_list_scans_exists(self, tmp_path):
        path = tmp_path / "scan.json"
        storage = JsonStorage(path)
        storage.save_manifest(_make_manifest(), "my_scan")
        result = storage.list_scans()
        assert len(result) == 1
        assert result[0]["name"] == "my_scan"
        assert result[0]["total_files"] == 2

    def test_delete_scan(self, tmp_path):
        path = tmp_path / "scan.json"
        storage = JsonStorage(path)
        storage.save_manifest(_make_manifest(), "x")
        assert path.exists()
        assert storage.delete_scan("x") is True
        assert not path.exists()

    def test_delete_missing(self, tmp_path):
        storage = JsonStorage(tmp_path / "missing.json")
        assert storage.delete_scan("x") is False

    def test_rename_scan(self, tmp_path):
        path = tmp_path / "scan.json"
        storage = JsonStorage(path)
        storage.save_manifest(_make_manifest(), "old")
        assert storage.rename_scan("old", "new") is True
        with open(path) as f:
            assert json.load(f)["name"] == "new"


# =================== SQLiteStorage ===================

class TestSQLiteStorage:
    def test_schema_created(self, tmp_path):
        db = tmp_path / "test.db"
        SQLiteStorage(db)
        assert db.exists()

    def test_save_and_load(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        m = _make_manifest()
        storage.save_manifest(m, "scan_one")
        loaded = storage.load_manifest("scan_one")
        assert len(loaded.files) == 2
        assert loaded.files["folder/file_0.jpg"].hash_content == "content_hash_0"

    def test_load_by_scan_id(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        m = _make_manifest()
        storage.save_manifest(m, "alias")
        loaded = storage.load_manifest(m.scan_id)
        assert loaded.scan_id == m.scan_id

    def test_load_missing_raises(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        with pytest.raises(FileNotFoundError):
            storage.load_manifest("nonexistent")

    def test_list_scans_ordered(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        storage.save_manifest(_make_manifest("a"), "A")
        storage.save_manifest(_make_manifest("b"), "B")
        storage.save_manifest(_make_manifest("c"), "C")
        scans = storage.list_scans()
        assert len(scans) == 3
        names = [s["name"] for s in scans]
        # Самый свежий — первый
        assert names == ["C", "B", "A"]

    def test_delete_scan_cascades_files(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        storage.save_manifest(_make_manifest("a", 3), "to_delete")
        storage.save_manifest(_make_manifest("b", 2), "to_keep")
        assert storage.delete_scan("to_delete") is True
        scans = storage.list_scans()
        assert len(scans) == 1
        assert scans[0]["name"] == "to_keep"

    def test_rename_scan(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        storage.save_manifest(_make_manifest(), "old_name")
        assert storage.rename_scan("old_name", "new_name") is True
        scans = storage.list_scans()
        assert scans[0]["name"] == "new_name"

    def test_same_directory_multiple_scans(self, tmp_path):
        """Критично: два скана одной директории не должны перезаписывать друг друга"""
        storage = SQLiteStorage(tmp_path / "t.db")
        m1 = _make_manifest("first")
        m2 = _make_manifest("second")
        # Эмулируем реальный случай: одинаковый scan_id
        m2.scan_id = m1.scan_id
        storage.save_manifest(m1, "Scan A")
        storage.save_manifest(m2, "Scan B")
        scans = storage.list_scans()
        assert len(scans) == 2
        names = {s["name"] for s in scans}
        assert names == {"Scan A", "Scan B"}

    def test_signature_verification(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        m = _make_manifest()
        sig = config.sign_report(asdict(m))
        storage.save_manifest(m, "signed", signature=sig)
        result = storage.verify_signature("signed")
        assert result["exists"] is True
        assert result["has_signature"] is True
        assert result["valid"] is True

    def test_signature_tampered(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        m = _make_manifest()
        storage.save_manifest(m, "tampered", signature="deadbeef" * 8)
        result = storage.verify_signature("tampered")
        assert result["valid"] is False

    def test_export_to_json(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        m = _make_manifest()
        sig = config.sign_report(asdict(m))
        storage.save_manifest(m, "export_me", signature=sig, notes="note")
        out = tmp_path / "out.json"
        storage.export_to_json("export_me", out)
        with open(out) as f:
            data = json.load(f)
        assert data["name"] == "export_me"
        assert data["notes"] == "note"
        assert data["_signature"] == sig
        assert len(data["files"]) == 2

    def test_import_from_json(self, tmp_path):
        # Создаём JSON-файл через JsonStorage
        json_path = tmp_path / "legacy.json"
        js = JsonStorage(json_path)
        m = _make_manifest()
        sig = config.sign_report(asdict(m))
        js.save_manifest(m, "legacy", signature=sig)

        # Импортируем в SQLite
        storage = SQLiteStorage(tmp_path / "t.db")
        storage.import_from_json(json_path, "imported")
        scans = storage.list_scans()
        assert len(scans) == 1
        assert scans[0]["name"] == "imported"
        loaded = storage.load_manifest("imported")
        assert len(loaded.files) == 2

    def test_metadata_json_stored(self, tmp_path):
        """Проверяем, что метаданные сериализуются в JSON и десериализуются обратно"""
        storage = SQLiteStorage(tmp_path / "t.db")
        m = _make_manifest()
        storage.save_manifest(m, "meta_test")
        loaded = storage.load_manifest("meta_test")
        f0 = loaded.files["folder/file_0.jpg"]
        assert f0.metadata["EXIF DateTimeOriginal"] == "2025-01-01T00:00:00+00:00"

    def test_warnings_stored(self, tmp_path):
        storage = SQLiteStorage(tmp_path / "t.db")
        m = _make_manifest()
        m.warnings = ["err1", "err2"]
        storage.save_manifest(m, "w")
        loaded = storage.load_manifest("w")
        assert loaded.warnings == ["err1", "err2"]