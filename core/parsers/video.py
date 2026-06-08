# core/parsers/video.py
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any

try:
    from mutagen.mp4 import MP4
    HAS_MUTAGEN = True
except ImportError:
    HAS_MUTAGEN = False

def parse_video_metadata(file_path: Path) -> Dict[str, Any]:
    """Извлекаем метаданные из MP4/MOV файлов"""
    if not HAS_MUTAGEN:
        return {"_parse_error": "mutagen not installed"}
    
    meta = {}
    try:
        mp4 = MP4(file_path)
        
        if mp4.tags:
            if '\xa9day' in mp4.tags:
                date_str = mp4.tags['\xa9day'][0]
                meta['creation_date'] = _normalize_date(date_str)
            
            if '\xa9ART' in mp4.tags:
                meta['artist'] = mp4.tags['\xa9ART'][0]
            
            if '\xa9alb' in mp4.tags:
                meta['album'] = mp4.tags['\xa9alb'][0]
            
            if '\xa9cmt' in mp4.tags:
                meta['comment'] = mp4.tags['\xa9cmt'][0]
            
            if 'desc' in mp4.tags:
                meta['description'] = mp4.tags['desc'][0]
        
        if '\xa9xyz' in mp4.tags:
            meta['location'] = mp4.tags['\xa9xyz'][0]
        
        if mp4.info:
            meta['duration_seconds'] = round(mp4.info.length, 2)
            meta['bitrate'] = mp4.info.bitrate
        
    except Exception as e:
        meta['_parse_error'] = str(e)
    
    return meta

def _normalize_date(date_str: str) -> str:
    """Нормализуем дату в ISO формат"""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y"):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return date_str