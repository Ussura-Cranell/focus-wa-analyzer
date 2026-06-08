"""Тесты для extractor.py"""
import pytest
import tempfile
from pathlib import Path
from core.extractor import compute_sha256, compute_meta_hash, normalize_date, extract_file
import config


class TestComputeSha256:
    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        h = compute_sha256(f)
        assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_small_file(self, tmp_path):
        f = tmp_path / "hello.bin"
        f.write_bytes(b"hello")
        h = compute_sha256(f)
        assert len(h) == 64
        # SHA-256("hello") — известное значение
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_deterministic(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"same content")
        assert compute_sha256(f) == compute_sha256(f)

    def test_one_byte_difference(self, tmp_path):
        f1 = tmp_path / "a.bin"
        f2 = tmp_path / "b.bin"
        f1.write_bytes(b"data1")
        f2.write_bytes(b"data2")
        assert compute_sha256(f1) != compute_sha256(f2)


class TestComputeMetaHash:
    def test_empty_metadata(self):
        h = compute_meta_hash({})
        assert len(h) == 64

    def test_excludes_unstable_fields(self):
        m1 = {
            "EXIF DateTimeOriginal": "2025-01-01T00:00:00",
            "fs_created": "2026-06-02T10:00:00",
            "fs_modified": "2026-06-02T10:00:01",
            "absolute_path": "/tmp/whatever",
        }
        m2 = {
            "EXIF DateTimeOriginal": "2025-01-01T00:00:00",
            "fs_created": "2099-01-01T00:00:00",  # другая дата
            "fs_modified": "2099-01-01T00:00:00",
            "absolute_path": "/completely/different",
        }
        # Несмотря на разные fs_* и absolute_path, хеши должны совпадать
        assert compute_meta_hash(m1) == compute_meta_hash(m2)

    def test_sensitive_field_changes_hash(self):
        m1 = {"EXIF DateTimeOriginal": "2025-01-01T00:00:00"}
        m2 = {"EXIF DateTimeOriginal": "2025-01-02T00:00:00"}
        assert compute_meta_hash(m1) != compute_meta_hash(m2)

    def test_gps_changes_hash(self):
        m1 = {"GPS GPSLatitude": "[55, 45, 0/1]"}
        m2 = {"GPS GPSLatitude": "[55, 46, 0/1]"}
        assert compute_meta_hash(m1) != compute_meta_hash(m2)

    def test_order_independent(self):
        m1 = {"A": "1", "B": "2", "C": "3"}
        m2 = {"C": "3", "A": "1", "B": "2"}
        assert compute_meta_hash(m1) == compute_meta_hash(m2)


class TestNormalizeDate:
    def test_exif_format(self):
        assert normalize_date("2025:01:15 10:30:00") == "2025-01-15T10:30:00+00:00"

    def test_iso_format(self):
        assert normalize_date("2025-01-15 10:30:00") == "2025-01-15T10:30:00+00:00"

    def test_compact_format(self):
        assert normalize_date("20250115T103000Z") == "2025-01-15T10:30:00+00:00"

    def test_unknown_format_passthrough(self):
        assert normalize_date("weird-date") == "weird-date"

    def test_strips_whitespace(self):
        assert normalize_date("  2025:01:15 10:30:00  ") == "2025-01-15T10:30:00+00:00"


class TestExtractFile:
    def test_extract_real_jpg(self):
        """Берём реальный тестовый JPG и проверяем поля"""
        jpg = Path("tests/test_assets/baseline/DSCN0010.jpg")
        if not jpg.exists():
            pytest.skip("Test asset not found")
        root = jpg.parent.parent
        rec = extract_file(jpg, root)
        assert rec.relative_path == "baseline/DSCN0010.jpg"
        assert rec.size_bytes == jpg.stat().st_size
        assert len(rec.hash_content) == 64
        assert len(rec.hash_meta) == 64
        assert rec.declared_ext == ".jpg"
        assert rec.real_mime == "image/jpeg"
        assert rec.match_status == "MATCH"
        assert rec.is_media is True
        assert rec.is_document is False

    def test_extract_detects_spoofed_exe(self):
        exe = Path("tests/test_assets/forensic/spoofed_exe.jpg")
        if not exe.exists():
            pytest.skip("Test asset not found")
        root = exe.parent.parent
        rec = extract_file(exe, root)
        assert rec.match_status == "MISMATCH"
        assert rec.real_mime == "application/x-msdownload"

    def test_extract_handles_missing_metadata(self):
        jpg = Path("tests/test_assets/baseline/image00971.jpg")
        if not jpg.exists():
            pytest.skip("Test asset not found")
        root = jpg.parent.parent
        rec = extract_file(jpg, root)
        # Даже без EXIF хеши должны считаться
        assert rec.hash_content
        assert rec.hash_meta

    def test_extract_preserves_all_exif(self):
        """Должны сохраняться ВСЕ EXIF-теги, а не только отфильтрованные"""
        jpg = Path("tests/test_assets/baseline/DSCN0010.jpg")
        if not jpg.exists():
            pytest.skip("Test asset not found")
        root = jpg.parent.parent
        rec = extract_file(jpg, root)
        assert "EXIF DateTimeOriginal" in rec.metadata
        assert "GPS GPSLatitude" in rec.metadata
        assert "Image Make" in rec.metadata or "Image Model" in rec.metadata

class TestParserIntegration:
    """Проверяет, что extractor использует все парсеры."""

    def test_pdf_metadata_extracted(self, tmp_path):
        """Создаём минимальный PDF и проверяем, что извлекается количество страниц."""
        try:
            from pypdf import PdfWriter
        except ImportError:
            pytest.skip("pypdf not installed")
        
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        p = tmp_path / "sample.pdf"
        with open(p, "wb") as f:
            writer.write(f)
            
        from core.extractor import extract_file
        rec = extract_file(p, tmp_path)
        assert rec.metadata.get("PDF Pages") == 1

    def test_docx_metadata_extracted(self, tmp_path):
        import zipfile
        core_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
            ' xmlns:dc="http://purl.org/dc/elements/1.1/">'
            '<dc:creator>Test Author</dc:creator>'
            '</cp:coreProperties>'
        )
        p = tmp_path / "doc.docx"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("docProps/core.xml", core_xml)
        from core.extractor import extract_file
        rec = extract_file(p, tmp_path)
        assert rec.metadata.get("Office Author") == "Test Author"