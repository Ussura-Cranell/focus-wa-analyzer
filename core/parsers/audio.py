"""Извлечение метаданных аудио (MP3/M4A/FLAC/OGG) через mutagen."""
from pathlib import Path
from typing import Dict, Any

try:
    import mutagen
    from mutagen.easyid3 import EasyID3
    from mutagen.mp4 import MP4
    from mutagen.flac import FLAC
    from mutagen.oggvorbis import OggVorbis
    HAS_MUTAGEN_AUDIO = True
except ImportError:
    HAS_MUTAGEN_AUDIO = False


def parse_audio_metadata(file_path: Path) -> Dict[str, Any]:
    if not HAS_MUTAGEN_AUDIO:
        return {"_parse_error": "mutagen not installed"}
    meta: Dict[str, Any] = {}
    try:
        ext = file_path.suffix.lower()
        if ext == ".mp3":
            _parse_id3(file_path, meta)
        elif ext in {".m4a", ".m4b", ".mp4"}:
            _parse_mp4(file_path, meta)
        elif ext == ".flac":
            _parse_flac(file_path, meta)
        elif ext == ".ogg":
            _parse_ogg(file_path, meta)
        else:
            # Fallback — общий EasyID3
            try:
                tags = EasyID3(str(file_path))
                _collect_easy_tags(tags, meta)
            except Exception:
                pass
    except Exception as e:
        meta["_parse_error"] = str(e)
    return meta


def _parse_id3(path: Path, meta: Dict[str, Any]):
    try:
        tags = EasyID3(str(path))
        _collect_easy_tags(tags, meta)
    except mutagen.id3.ID3NoHeaderError:
        pass
    audio = mutagen.File(str(path))
    if audio and audio.info:
        meta["Audio Duration"] = f"{audio.info.length:.2f}s"
        if hasattr(audio.info, "bitrate"):
            meta["Audio Bitrate"] = audio.info.bitrate


def _parse_mp4(path: Path, meta: Dict[str, Any]):
    mp4 = MP4(str(path))
    tag_map = {
        "\xa9nam": "Audio Title", "\xa9ART": "Audio Artist",
        "\xa9alb": "Audio Album", "\xa9day": "Audio Date",
        "\xa9cmt": "Audio Comment", "\xa9gen": "Audio Genre",
        "aART": "Audio AlbumArtist",
    }
    if mp4.tags:
        for k, out in tag_map.items():
            if k in mp4.tags and mp4.tags[k]:
                meta[out] = str(mp4.tags[k][0])
    if mp4.info:
        meta["Audio Duration"] = f"{mp4.info.length:.2f}s"


def _parse_flac(path: Path, meta: Dict[str, Any]):
    flac = FLAC(str(path))
    _collect_vorbis(flac, meta)
    if flac.info:
        meta["Audio Duration"] = f"{flac.info.length:.2f}s"
        meta["Audio Bitrate"] = flac.info.bitrate


def _parse_ogg(path: Path, meta: Dict[str, Any]):
    ogg = OggVorbis(str(path))
    _collect_vorbis(ogg, meta)
    if ogg.info:
        meta["Audio Duration"] = f"{ogg.info.length:.2f}s"
        meta["Audio Bitrate"] = ogg.info.bitrate


def _collect_easy_tags(tags, meta: Dict[str, Any]):
    mapping = {
        "title": "Audio Title", "artist": "Audio Artist",
        "album": "Audio Album", "date": "Audio Date",
        "genre": "Audio Genre", "albumartist": "Audio AlbumArtist",
    }
    for k, out in mapping.items():
        try:
            vals = tags.get(k)
            if vals:
                meta[out] = str(vals[0])
        except Exception:
            continue


def _collect_vorbis(tags, meta: Dict[str, Any]):
    if not tags.tags:
        return
    mapping = {
        "title": "Audio Title", "artist": "Audio Artist",
        "album": "Audio Album", "date": "Audio Date",
        "genre": "Audio Genre",
    }
    for k, out in mapping.items():
        if k in tags.tags and tags.tags[k]:
            meta[out] = str(tags.tags[k][0])