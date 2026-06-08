"""Извлечение метаданных Office-документов (DOCX/XLSX/PPTX) без внешних зависимостей.
Все эти форматы — ZIP-архивы с XML внутри. Нас интересует docProps/core.xml."""
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any


NAMESPACES = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
}


def parse_office_metadata(file_path: Path) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    try:
        with zipfile.ZipFile(file_path) as zf:
            if "docProps/core.xml" not in zf.namelist():
                return {"_parse_error": "docProps/core.xml not found"}
            with zf.open("docProps/core.xml") as f:
                tree = ET.parse(f)
            root = tree.getroot()

        field_map = [
            ("dc:creator", "Office Author"),
            ("dc:title", "Office Title"),
            ("dc:subject", "Office Subject"),
            ("dc:description", "Office Description"),
            ("cp:keywords", "Office Keywords"),
            ("cp:lastModifiedBy", "Office LastModifiedBy"),
            ("cp:revision", "Office Revision"),
            ("cp:category", "Office Category"),
            ("dcterms:created", "Office Created"),
            ("dcterms:modified", "Office Modified"),
        ]
        for xpath, out_key in field_map:
            el = root.find(xpath, NAMESPACES)
            if el is not None and el.text:
                meta[out_key] = el.text.strip()
    except zipfile.BadZipFile:
        meta["_parse_error"] = "not a valid zip/office file"
    except Exception as e:
        meta["_parse_error"] = str(e)
    return meta