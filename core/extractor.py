import hashlib
import json
import exifread
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any
import config
from .profiler import profile_file
from .models import FileRecord

def compute_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(config.CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()

def compute_meta_hash(metadata: dict, full_compare: bool = False) -> str:
    """
    Вычисляет хеш метаданных.
    
    Args:
        metadata: словарь метаданных
        full_compare: если True, хеширует ВСЕ поля; если False - только стабильные
    
    Returns:
        SHA-256 хеш нормализованных метаданных
    """
    if full_compare:
        # Режим полного сравнения: хешируем ВСЁ
        clean = {
            k: v for k, v in metadata.items()
            if k not in config.EXCLUDE_FROM_META_HASH
        }
    else:
        # Режим стабильного сравнения: только фиксированные поля
        clean = {
            k: v for k, v in metadata.items()
            if k in config.STABLE_META_FIELDS and k not in config.EXCLUDE_FROM_META_HASH
        }
    
    # Детерминированная сериализация для стабильного хеша
    data = json.dumps(clean, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def normalize_date(date_str: str) -> str:
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y%m%dT%H%M%SZ"):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return date_str

def extract_metadata(file_path: Path, profile: Dict[str, Any]) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    ext = file_path.suffix.lower()
    mime = profile.get("real_mime", "") or ""
    try:
        # JPEG/PNG/HEIC — EXIF
        if ext in {".jpg", ".jpeg", ".png", ".heic"} or mime.startswith("image/"):
            with open(file_path, "rb") as f:
                tags = exifread.process_file(f, details=False, strict=True)
            for key, val in tags.items():
                k = str(key)
                meta[k] = normalize_date(str(val)) if "DateTime" in k else str(val)

        # MP4/MOV/M4V — видео
        elif ext in {".mp4", ".mov", ".m4v"} or mime.startswith("video/"):
            from .parsers.video import parse_video_metadata
            meta.update(parse_video_metadata(file_path))

        # MP3/M4A/FLAC/OGG/AAC/WAV — аудио
        elif ext in {".mp3", ".m4a", ".flac", ".ogg", ".aac", ".wav", ".opus"} \
                or mime.startswith("audio/"):
            from .parsers.audio import parse_audio_metadata
            meta.update(parse_audio_metadata(file_path))

        # PDF — документы
        elif ext == ".pdf" or mime == "application/pdf":
            from .parsers.pdf import parse_pdf_metadata
            meta.update(parse_pdf_metadata(file_path))

        # DOCX/XLSX/PPTX — офис
        elif ext in {".docx", ".xlsx", ".pptx"}:
            from .parsers.office import parse_office_metadata
            meta.update(parse_office_metadata(file_path))

        # Всё остальное — только FS-даты
        else:
            stat = file_path.stat()
            meta["fs_created"] = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()
            meta["fs_modified"] = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

    except Exception as e:
        meta["_parse_error"] = str(e)
    return meta

def extract_file(file_path: Path, root: Path, strict: bool = False, full_meta_compare: bool = False) -> FileRecord:
    profile = profile_file(file_path, strict)
    hash_content = compute_sha256(file_path)
    metadata = extract_metadata(file_path, profile)
    
    # ✅ Передаём флаг full_meta_compare в compute_meta_hash
    hash_meta = compute_meta_hash(metadata, full_compare=full_meta_compare)
    
    now = datetime.now(timezone.utc).isoformat()
    
    return FileRecord(
        relative_path=str(file_path.relative_to(root)),
        absolute_path=str(file_path.resolve()),
        size_bytes=file_path.stat().st_size,
        hash_content=hash_content,
        hash_meta=hash_meta,
        declared_ext=profile["declared_ext"],
        real_mime=profile["real_mime"],
        match_status=profile["match_status"],
        is_media=profile["is_media"],
        is_document=profile["is_document"],
        metadata=metadata,
        scan_timestamp=now
    )