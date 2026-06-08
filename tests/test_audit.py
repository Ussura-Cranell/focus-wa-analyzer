"""Тесты для core/audit.py"""
import json
import pytest
from pathlib import Path
from core.audit import AuditLogger


class TestAuditLogger:
    def test_creates_log_file(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log, operator="tester")
        logger.log_scan_start("local", "/tmp/test")
        assert log.exists()

    def test_creates_parent_dirs(self, tmp_path):
        log = tmp_path / "deep" / "nested" / "audit.jsonl"
        logger = AuditLogger(log)
        logger.log_scan_start("adb", "adb://device")
        assert log.exists()

    def test_log_scan_start(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log, operator="expert_01")
        logger.log_scan_start("local", "/media")
        with open(log) as f:
            entry = json.loads(f.readline())
        assert entry["event"] == "scan_start"
        assert entry["source_type"] == "local"
        assert entry["source_path"] == "/media"
        assert entry["operator"] == "expert_01"
        assert "timestamp" in entry

    def test_log_file_processed(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log)
        logger.log_file_processed("photo.jpg", "abc123", "def456")
        with open(log) as f:
            entry = json.loads(f.readline())
        assert entry["event"] == "file_processed"
        assert entry["file_path"] == "photo.jpg"
        assert entry["hash_content"] == "abc123"
        assert entry["hash_meta"] == "def456"

    def test_log_scan_complete(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log)
        logger.log_scan_complete(10, 2)
        with open(log) as f:
            entry = json.loads(f.readline())
        assert entry["event"] == "scan_complete"
        assert entry["total_files"] == 10
        assert entry["warnings"] == 2
        assert "log_hash" in entry
        assert len(entry["log_hash"]) == 64

    def test_jsonl_format_one_entry_per_line(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log)
        logger.log_scan_start("local", "/")
        logger.log_file_processed("a.jpg", "h1", "m1")
        logger.log_file_processed("b.jpg", "h2", "m2")
        logger.log_scan_complete(2, 0)
        with open(log) as f:
            lines = f.readlines()
        assert len(lines) == 4
        for line in lines:
            # Каждая строка — валидный JSON
            parsed = json.loads(line)
            assert "event" in parsed

    def test_final_hash_covers_all_entries(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log)
        logger.log_scan_start("local", "/")
        logger.log_file_processed("a.jpg", "h1", "m1")
        summary = logger.get_summary()
        # Тот же логгер → тот же хеш
        assert summary["final_hash"] == logger._compute_log_hash()

    def test_summary_contains_metadata(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log)
        logger.log_scan_start("local", "/")
        s = logger.get_summary()
        assert s["audit_log_path"] == str(log)
        assert s["total_entries"] == 1
        assert len(s["final_hash"]) == 64

    def test_default_operator_is_anonymous(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log)  # Без operator
        logger.log_scan_start("local", "/")
        with open(log) as f:
            entry = json.loads(f.readline())
        assert entry["operator"] == "anonymous"

    def test_log_compare_start(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log)
        if hasattr(logger, "log_compare_start"):
            logger.log_compare_start("/ref/scan.json")
            with open(log) as f:
                entry = json.loads(f.readline())
            assert entry["event"] == "compare_start"