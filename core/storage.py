# core/storage.py
import sqlite3
import json
import hashlib
import hmac
from abc import ABC, abstractmethod
from pathlib import Path
from dataclasses import asdict
from typing import Optional
from .models import ScanManifest, FileRecord
import config


class Storage(ABC):
    @abstractmethod
    def save_manifest(self, manifest: ScanManifest, name: str,
                      signature: Optional[str] = None, notes: str = "") -> str:
        pass

    @abstractmethod
    def load_manifest(self, identifier: str) -> ScanManifest:
        pass

    @abstractmethod
    def list_scans(self) -> list[dict]:
        pass

    @abstractmethod
    def get_scan_meta(self, identifier: str) -> Optional[dict]:
        pass

    @abstractmethod
    def delete_scan(self, identifier: str) -> bool:
        pass

    @abstractmethod
    def rename_scan(self, old_name: str, new_name: str) -> bool:
        pass


class JsonStorage(Storage):
    """Обратная совместимость — работа с JSON-файлами"""

    def __init__(self, path: Path):
        self.path = Path(path)

    def save_manifest(self, manifest: ScanManifest, name: str,
                      signature: Optional[str] = None, notes: str = "") -> str:
        data = asdict(manifest)
        data["name"] = name
        data["notes"] = notes
        if signature:
            data["_signature"] = signature
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        return str(self.path)

    def load_manifest(self, identifier: str) -> ScanManifest:
        with open(identifier, "r", encoding="utf-8") as f:
            data = json.load(f)
        return self._dict_to_manifest(data)

    def list_scans(self) -> list[dict]:
        if not self.path.exists():
            return []
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [{
            "scan_id": data.get("scan_id", ""),
            "name": data.get("name", self.path.stem),
            "source_root": data.get("source_root", ""),
            "total_files": len(data.get("files", {})),
            "scan_timestamp": data.get("scan_timestamp", ""),
            "has_signature": "_signature" in data,
        }]

    def get_scan_meta(self, identifier: str) -> Optional[dict]:
        if not self.path.exists():
            return None
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "scan_id": data.get("scan_id", ""),
            "name": data.get("name", ""),
            "source_root": data.get("source_root", ""),
            "total_files": len(data.get("files", {})),
            "has_signature": "_signature" in data,
            "signature": data.get("_signature"),
        }

    def delete_scan(self, identifier: str) -> bool:
        if self.path.exists():
            self.path.unlink()
            return True
        return False

    def rename_scan(self, old_name: str, new_name: str) -> bool:
        if not self.path.exists():
            return False
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["name"] = new_name
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        return True

    def _dict_to_manifest(self, data: dict) -> ScanManifest:
        files = {}
        for path, fdata in data.get("files", {}).items():
            files[path] = FileRecord(
                relative_path=fdata.get("relative_path", path),
                absolute_path=fdata.get("absolute_path", ""),
                size_bytes=fdata.get("size_bytes", 0),
                hash_content=fdata.get("hash_content", ""),
                hash_meta=fdata.get("hash_meta", ""),
                declared_ext=fdata.get("declared_ext", ""),
                real_mime=fdata.get("real_mime"),
                match_status=fdata.get("match_status", "UNKNOWN"),
                is_media=fdata.get("is_media", False),
                is_document=fdata.get("is_document", False),
                metadata=fdata.get("metadata", {}),
                scan_timestamp=fdata.get("scan_timestamp", ""),
            )
        return ScanManifest(
            scan_id=data.get("scan_id", ""),
            source_root=data.get("source_root", ""),
            scan_timestamp=data.get("scan_timestamp", ""),
            files=files,
            warnings=data.get("warnings", []),
        )


class SQLiteStorage(Storage):
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        source_type TEXT,
        source_root TEXT,
        device_id TEXT,
        scan_timestamp TEXT,
        total_files INTEGER,
        warnings_count INTEGER,
        signature TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        relative_path TEXT NOT NULL,
        absolute_path TEXT,
        size_bytes INTEGER,
        hash_content TEXT NOT NULL,
        hash_meta TEXT NOT NULL,
        declared_ext TEXT,
        real_mime TEXT,
        match_status TEXT,
        is_media INTEGER,
        is_document INTEGER,
        metadata_json TEXT,
        scan_timestamp TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
        UNIQUE(scan_id, relative_path)
    );
    CREATE TABLE IF NOT EXISTS warnings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        message TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_files_scan_path ON files(scan_id, relative_path);
    CREATE INDEX IF NOT EXISTS idx_files_hash_content ON files(hash_content);
    CREATE INDEX IF NOT EXISTS idx_files_hash_meta ON files(hash_meta);
    CREATE INDEX IF NOT EXISTS idx_scans_name ON scans(name);
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(self.SCHEMA)

    def save_manifest(self, manifest: ScanManifest, name: str,
                      signature: Optional[str] = None, notes: str = "") -> str:
        scan_id = manifest.scan_id
        
        # 🔧 Защита от коллизии scan_id: если такой scan_id уже есть с другим name,
        # генерируем уникальный, чтобы два скана одной папки не перезатирали друг друга
        with self._conn() as conn:
            conflict = conn.execute(
                "SELECT name FROM scans WHERE scan_id = ? AND name != ?",
                (scan_id, name)
            ).fetchone()
            if conflict:
                import uuid
                scan_id = f"{scan_id}_{uuid.uuid4().hex[:8]}"
        
        with self._conn() as conn:
            source_type = "local" if manifest.source_root != "adb://device" else "adb"
            device_id = scan_id.split("_")[1] if source_type == "adb" and "_" in scan_id else None
            
            conn.execute("""
                INSERT OR REPLACE INTO scans
                (scan_id, name, source_type, source_root, device_id,
                 scan_timestamp, total_files, warnings_count, signature, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, name, source_type, manifest.source_root,
                  device_id, manifest.scan_timestamp, len(manifest.files),
                  len(manifest.warnings), signature, notes))
            
            # Удаляем старые файлы/предупреждения для этого scan_id
            conn.execute("DELETE FROM files WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM warnings WHERE scan_id = ?", (scan_id,))
            
            for rec in manifest.files.values():
                conn.execute("""
                    INSERT INTO files
                    (scan_id, relative_path, absolute_path, size_bytes,
                     hash_content, hash_meta, declared_ext, real_mime,
                     match_status, is_media, is_document, metadata_json, scan_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (scan_id, rec.relative_path, rec.absolute_path,
                      rec.size_bytes, rec.hash_content, rec.hash_meta,
                      rec.declared_ext, rec.real_mime, rec.match_status,
                      int(rec.is_media), int(rec.is_document),
                      json.dumps(rec.metadata, ensure_ascii=False, default=str),
                      rec.scan_timestamp))
            
            for w in manifest.warnings:
                conn.execute("INSERT INTO warnings (scan_id, message) VALUES (?, ?)",
                             (scan_id, w))
        
        return f"{self.db_path}:{name}"

    def load_manifest(self, identifier: str) -> ScanManifest:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE name = ? OR scan_id = ?",
                (identifier, identifier)
            ).fetchone()
            if not row:
                raise FileNotFoundError(f"Scan not found: {identifier}")

            files = {}
            for fr in conn.execute(
                "SELECT * FROM files WHERE scan_id = ?", (row["scan_id"],)
            ).fetchall():
                files[fr["relative_path"]] = FileRecord(
                    relative_path=fr["relative_path"],
                    absolute_path=fr["absolute_path"] or "",
                    size_bytes=fr["size_bytes"] or 0,
                    hash_content=fr["hash_content"],
                    hash_meta=fr["hash_meta"],
                    declared_ext=fr["declared_ext"] or "",
                    real_mime=fr["real_mime"],
                    match_status=fr["match_status"] or "UNKNOWN",
                    is_media=bool(fr["is_media"]),
                    is_document=bool(fr["is_document"]),
                    metadata=json.loads(fr["metadata_json"] or "{}"),
                    scan_timestamp=fr["scan_timestamp"] or "",
                )

            warnings = [r["message"] for r in conn.execute(
                "SELECT message FROM warnings WHERE scan_id = ?",
                (row["scan_id"],)
            ).fetchall()]

            return ScanManifest(
                scan_id=row["scan_id"],
                source_root=row["source_root"] or "",
                scan_timestamp=row["scan_timestamp"] or "",
                files=files,
                warnings=warnings,
            )

    def get_scan_meta(self, identifier: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE name = ? OR scan_id = ?",
                (identifier, identifier)
            ).fetchone()
            return dict(row) if row else None

    def list_scans(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT scan_id, name, source_type, source_root, device_id, "
                "scan_timestamp, total_files, warnings_count, signature, notes, created_at "
                "FROM scans ORDER BY created_at DESC, scan_id DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_scan(self, identifier: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM scans WHERE name = ? OR scan_id = ?",
                (identifier, identifier)
            )
            return cur.rowcount > 0

    def rename_scan(self, old_name: str, new_name: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE scans SET name = ? WHERE name = ? OR scan_id = ?",
                (new_name, old_name, old_name)
            )
            return cur.rowcount > 0

    def verify_signature(self, name: str) -> dict:
        meta = self.get_scan_meta(name)
        if not meta:
            return {"exists": False}
        stored = meta.get("signature")
        if not stored:
            return {"exists": True, "has_signature": False}

        # Загружаем манифест и вычисляем хеш
        manifest = self.load_manifest(name)
        data = asdict(manifest)
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=False, default=str).encode()
        computed = hmac.new(config.REPORT_HMAC_KEY, canonical, hashlib.sha256).hexdigest()
        return {
            "exists": True,
            "has_signature": True,
            "valid": hmac.compare_digest(stored, computed),
            "stored": stored,
            "computed": computed,
        }

    def export_to_json(self, name: str, output_path: Path) -> Path:
        manifest = self.load_manifest(name)
        data = asdict(manifest)
        meta = self.get_scan_meta(name)
        data["name"] = name
        if meta:
            if meta.get("notes"):
                data["notes"] = meta["notes"]
            if meta.get("signature"):
                data["_signature"] = meta["signature"]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        return output_path

    def import_from_json(self, json_path: Path, name: str) -> str:
        js = JsonStorage(json_path)
        manifest = js.load_manifest(str(json_path))  # 🔧 ЭТА СТРОКА БЫЛА ПРОПУЩЕНА
        with open(json_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        signature = raw.get("_signature")
        notes = raw.get("notes", "")
        return self.save_manifest(manifest, name, signature=signature, notes=notes)