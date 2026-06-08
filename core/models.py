from dataclasses import dataclass, field
from typing import Optional

@dataclass
class FileRecord:
    relative_path: str
    absolute_path: str
    size_bytes: int
    hash_content: str      # SHA-256 байтов файла
    hash_meta: str         # SHA-256 нормализованных метаданных
    declared_ext: str
    real_mime: Optional[str]
    match_status: str      # MATCH / MISMATCH / UNKNOWN
    is_media: bool
    is_document: bool
    metadata: dict
    scan_timestamp: str

@dataclass
class ScanManifest:
    scan_id: str
    source_root: str
    scan_timestamp: str
    files: dict[str, FileRecord] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

@dataclass
class DiffEntry:
    path: str
    status: str
    details: dict