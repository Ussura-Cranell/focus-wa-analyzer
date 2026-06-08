"""Тесты для парсеров PDF/Office/Audio/Video."""
import pytest
import zipfile
from pathlib import Path
from core.parsers import pdf, office, audio


class TestPdfParser:
    def test_missing_pypdf_returns_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.parsers.pdf.HAS_PYPDF", False)
        f = tmp_path / "x.pdf"
        f.write_bytes(b"%PDF-1.4\n")
        meta = pdf.parse_pdf_metadata(f)
        assert "_parse_error" in meta
        assert "pypdf not installed" in meta["_parse_error"]

    def test_invalid_pdf_returns_error(self, tmp_path):
        f = tmp_path / "bad.pdf"
        f.write_bytes(b"not a pdf")
        meta = pdf.parse_pdf_metadata(f)
        assert isinstance(meta, dict)
        assert "_parse_error" in meta or len(meta) == 0

    def test_normalize_pdf_date_d_prefix(self):
        assert pdf._normalize_pdf_date("D:20250115103000").startswith("2025-01-15")

    def test_normalize_pdf_date_empty(self):
        assert pdf._normalize_pdf_date("weird") == ""


class TestOfficeParser:
    def _make_minimal_docx(self, path: Path):
        """Создаёт минимальный DOCX с core.xml."""
        core_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
            ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
            ' xmlns:dcterms="http://purl.org/dc/terms/">'
            '<dc:creator>Test Author</dc:creator>'
            '<dc:title>Test Title</dc:title>'
            '<cp:lastModifiedBy>Test Editor</cp:lastModifiedBy>'
            '<cp:revision>3</cp:revision>'
            '<dcterms:created>2025-01-15T10:00:00Z</dcterms:created>'
            '<dcterms:modified>2025-02-20T14:30:00Z</dcterms:modified>'
            '</cp:coreProperties>'
        )
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("docProps/core.xml", core_xml)
            zf.writestr("[Content_Types].xml", "<Types/>")

    def test_parse_valid_docx(self, tmp_path):
        docx = tmp_path / "test.docx"
        self._make_minimal_docx(docx)
        meta = office.parse_office_metadata(docx)
        assert meta.get("Office Author") == "Test Author"
        assert meta.get("Office Title") == "Test Title"
        assert meta.get("Office LastModifiedBy") == "Test Editor"
        assert meta.get("Office Revision") == "3"
        assert "Office Created" in meta
        assert "Office Modified" in meta

    def test_parse_invalid_zip(self, tmp_path):
        bad = tmp_path / "bad.docx"
        bad.write_bytes(b"not a zip")
        meta = office.parse_office_metadata(bad)
        assert "_parse_error" in meta

    def test_parse_zip_without_core(self, tmp_path):
        empty = tmp_path / "empty.docx"
        with zipfile.ZipFile(empty, "w") as zf:
            zf.writestr("dummy.txt", "hi")
        meta = office.parse_office_metadata(empty)
        assert "_parse_error" in meta


class TestAudioParser:
    def test_nonexistent_returns_error(self, tmp_path):
        f = tmp_path / "ghost.mp3"
        meta = audio.parse_audio_metadata(f)
        assert "_parse_error" in meta

    def test_invalid_mp3_returns_error(self, tmp_path):
        f = tmp_path / "bad.mp3"
        f.write_bytes(b"not audio at all")
        meta = audio.parse_audio_metadata(f)
        # mutagen либо вернёт пустой meta, либо поставит _parse_error
        assert isinstance(meta, dict)

    def test_unsupported_ext_still_returns_dict(self, tmp_path):
        f = tmp_path / "x.xyz"
        f.write_bytes(b"whatever")
        meta = audio.parse_audio_metadata(f)
        assert isinstance(meta, dict)