"""Извлечение метаданных PDF через pypdf."""
from pathlib import Path
from typing import Dict, Any
from datetime import datetime, timezone

try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False


def parse_pdf_metadata(file_path: Path) -> Dict[str, Any]:
    if not HAS_PYPDF:
        return {"_parse_error": "pypdf not installed"}
    
    meta: Dict[str, Any] = {}
    try:
        reader = PdfReader(str(file_path))
        info = reader.metadata or {}

        field_map = {
            "/Title": "Title",
            "/Author": "Author",
            "/Subject": "Subject",
            "/Creator": "Creator",
            "/Producer": "Producer",
            "/Keywords": "Keywords",
        }
        for pdf_key, out_key in field_map.items():
            val = info.get(pdf_key)
            if val:
                meta[f"PDF {out_key}"] = str(val)

        for date_key, out_key in [("/CreationDate", "PDF CreationDate"),
                                   ("/ModDate", "PDF ModDate")]:
            val = info.get(date_key)
            if val:
                meta[out_key] = _normalize_pdf_date(str(val)) or str(val)

        meta["PDF Pages"] = len(reader.pages)
    except Exception as e:
        meta["_parse_error"] = str(e)
    
    return meta


def _normalize_pdf_date(s: str) -> str:
    """Преобразует 'D:20250115103000+0300' в ISO."""
    s = s.strip()
    if s.startswith("D:"):
        s = s[2:]
    
    # Убираем одинарные кавычки, которые иногда добавляет exiftool/PDF
    s = s.replace("'", "")
    
    for fmt in ("%Y%m%d%H%M%S%z", "%Y%m%d%H%M%S", "%Y%m%d"):
        try:
            dt = datetime.strptime(s[:20], fmt)
            return dt.replace(tzinfo=dt.tzinfo or timezone.utc).isoformat()
        except ValueError:
            continue
    return ""