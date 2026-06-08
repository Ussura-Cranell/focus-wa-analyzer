import filetype
from pathlib import Path
from typing import Dict, Any

# ✅ АБСОЛЮТНО ЧИСТЫЙ СЛОВАРЬ: никаких пробелов внутри кавычек!
VALID_MIME_TO_EXTS = {
    "image/jpeg": {".jpg", ".jpeg"},
    "image/png": {".png"},
    "image/gif": {".gif"},
    "image/bmp": {".bmp"},
    "image/heic": {".heic"},
    "video/mp4": {".mp4", ".m4v"},
    "video/quicktime": {".mov"},
    "video/x-msvideo": {".avi"},
    "video/x-matroska": {".mkv"},
    "video/webm": {".webm"},
    "audio/mpeg": {".mp3"},
    "audio/mp4": {".m4a", ".aac"},
    "audio/ogg": {".ogg", ".opus"},
    "audio/wav": {".wav"},
    "audio/wav": {".wav"},
    "audio/x-wav": {".wav"},
    "application/pdf": {".pdf"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {".pptx"},
    "application/zip": {".zip"},
}

def profile_file(file_path: Path, strict: bool = False) -> Dict[str, Any]:
    declared_ext = file_path.suffix.lower()
    real_mime = None
    match_status = "UNKNOWN"
    is_media = False
    is_document = False

    try:
        kind = filetype.guess(file_path)
        if kind:
            real_mime = kind.mime
            
            # Проверяем, является ли объявленное расширение допустимым для этого MIME
            valid_exts = VALID_MIME_TO_EXTS.get(real_mime, set())
            if declared_ext in valid_exts:
                match_status = "MATCH"
            else:
                match_status = "MISMATCH"
                
            is_media = real_mime.startswith(("image/", "video/", "audio/"))
            is_document = real_mime.startswith(("application/", "text/"))
            
        else:
            # Fallback: если сигнатура не распознана, доверяем расширению
            media_exts = {".jpg", ".jpeg", ".png", ".heic", ".mp4", ".mov", ".mp3", ".opus", ".wav"}
            doc_exts = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".txt", ".zip"}
            
            if declared_ext in media_exts:
                match_status, is_media = "MATCH", True
            elif declared_ext in doc_exts:
                match_status, is_document = "MATCH", True
                
    except Exception:
        match_status = "ERROR"

    return {
        "real_mime": real_mime,
        "declared_ext": declared_ext,
        "match_status": match_status,
        "is_media": is_media,
        "is_document": is_document
    }