import os
import hashlib
import hmac
import json

# Расширения для анализа (БЕЗ ПРОБЕЛОВ)
ALLOWED_EXTS = {
    ".jpg", ".jpeg", ".png", ".heic", ".gif", ".bmp",
    ".mp4", ".mov", ".avi", ".mkv", ".webm",
    ".mp3", ".m4a", ".opus", ".ogg", ".wav", ".aac",
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".zip"
}

CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB for streaming hash

# Поля, исключаемые из hash_meta (нестабильные при копировании)
EXCLUDE_FROM_META_HASH = {
    "fs_created",
    "fs_modified",
    "absolute_path",
    "_parse_error",
}

# Стабильные поля для hash_meta (по умолчанию)
# Эти поля не меняются при простом копировании файлов
STABLE_META_FIELDS = {
    # Временные метки съёмки
    "EXIF DateTimeOriginal",
    "EXIF DateTimeDigitized",
    "Image DateTime",
    
    # Геолокация
    "GPS GPSLatitude",
    "GPS GPSLatitudeRef",
    "GPS GPSLongitude",
    "GPS GPSLongitudeRef",
    "GPS GPSAltitude",
    "GPS GPSAltitudeRef",
    
    # Оборудование
    "Image Make",
    "Image Model",
    "EXIF LensModel",
    
    # Настройки съёмки
    "EXIF Software",
    "Image Orientation",
    
    # Версии GPS
    "GPS GPSVersionID",
}

DEFAULT_STRICT = False

# HMAC ключ для подписи отчётов
REPORT_HMAC_KEY = os.getenv("WA_ANALYZER_HMAC_KEY", "dev-key-change-in-prod").encode()

def sign_report(data: dict) -> str:
    """Создаёт HMAC-SHA256 подпись для JSON-отчёта"""
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return hmac.new(REPORT_HMAC_KEY, canonical, hashlib.sha256).hexdigest()

def verify_report(data: dict, signature: str) -> bool:
    """Проверяет подпись отчёта"""
    return hmac.compare_digest(sign_report(data), signature)