# core/audit.py
import json
import hashlib
import hmac
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
import config

logger = logging.getLogger(__name__)

class AuditLogger:
    """Безопасный аудитор для форензик-экспертизы"""
    
    def __init__(self, log_path: Path, operator: Optional[str] = None):
        self.log_path = log_path
        self.operator = operator or "anonymous"
        self.entries = []
        self._ensure_parent_dir()
    
    def _ensure_parent_dir(self):
        """Создаём директорию для лога, если её нет"""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _log_entry(self, event_type: str, details: dict):
        """Записываем одну запись в лог"""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "operator": self.operator,
            "version": "1.0.0",
            **details
        }
        self.entries.append(entry)
        
        # Сразу пишем в файл (JSON Lines формат)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    
    def log_scan_start(self, source_type: str, source_path: str):
        """Логируем начало сканирования"""
        self._log_entry("scan_start", {
            "source_type": source_type,
            "source_path": source_path
        })
    
    def log_file_processed(self, file_path: str, hash_content: str, hash_meta: str):
        """Логируем обработку файла"""
        self._log_entry("file_processed", {
            "file_path": file_path,
            "hash_content": hash_content,
            "hash_meta": hash_meta
        })
    
    def log_compare_start(self, reference_path: str):
        """Логируем начало сравнения"""
        self._log_entry("compare_start", {
            "reference_path": reference_path
        })
    
    def log_scan_complete(self, total_files: int, warnings: int):
        """Логируем завершение сканирования"""
        self._log_entry("scan_complete", {
            "total_files": total_files,
            "warnings": warnings,
            "log_hash": self._compute_log_hash()
        })
    
    def _compute_log_hash(self) -> str:
        """Вычисляем HMAC-SHA256 всех записей лога"""
        canonical = json.dumps(self.entries, sort_keys=True, ensure_ascii=False).encode()
        return hmac.new(config.REPORT_HMAC_KEY, canonical, hashlib.sha256).hexdigest()
    
    def get_summary(self) -> dict:
        """Возвращаем сводку для отчёта"""
        return {
            "audit_log_path": str(self.log_path),
            "total_entries": len(self.entries),
            "final_hash": self._compute_log_hash()
        }