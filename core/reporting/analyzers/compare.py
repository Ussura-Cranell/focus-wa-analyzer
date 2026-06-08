# core/reporting/analyzers/compare.py
"""Детальный анализ различий между двумя слепками."""
from typing import Dict, Any, List
from collections import defaultdict


class CompareAnalyzer:
    """Анализирует diff между baseline и текущим состоянием."""

    def __init__(self, old_files: Dict[str, Any], new_files: Dict[str, Any],
                 diff_entries: List[Dict[str, Any]]):
        self.old_files = old_files
        self.new_files = new_files
        self.diff_entries = diff_entries

    def analyze(self) -> Dict[str, Any]:
        return {
            "summary": self._summary(),
            "deletions": self._analyze_deletions(),
            "additions": self._analyze_additions(),
            "content_modifications": self._analyze_content_modifications(),
            "metadata_modifications": self._analyze_metadata_modifications(),
            "moves": self._analyze_moves(),
            "critical_findings": self._critical_findings(),
        }

    def _summary(self) -> Dict[str, Any]:
        from collections import Counter
        counts = Counter(e.get("status") for e in self.diff_entries)
        return {
            "total_changes": len(self.diff_entries),
            "added": counts.get("ADDED", 0),
            "deleted": counts.get("DELETED", 0),
            "content_modified": counts.get("CONTENT_MODIFIED", 0),
            "meta_modified": counts.get("META_MODIFIED", 0),
            "moved": counts.get("MOVED", 0),
        }

    def _analyze_deletions(self) -> Dict[str, Any]:
        """Детальный анализ удалённых файлов."""
        deletions = [e for e in self.diff_entries if e.get("status") == "DELETED"]
        with_gps = []
        with_dates = []
        total_size_lost = 0
        by_ext: Dict[str, int] = defaultdict(int)

        for e in deletions:
            old_f = self.old_files.get(e.get("path", ""), {})
            meta = old_f.get("metadata", {})
            size = old_f.get("size_bytes", 0)
            total_size_lost += size
            ext = old_f.get("declared_ext", ".unknown")
            by_ext[ext] += 1

            if any("GPS" in k for k in meta):
                with_gps.append({
                    "path": e.get("path"),
                    "hash": e.get("details", {}).get("old_hash", ""),
                    "size_mb": round(size / (1024 * 1024), 2),
                    "had_gps": True,
                })
            if any("DateTime" in k for k in meta):
                with_dates.append(e.get("path"))

        return {
            "count": len(deletions),
            "total_size_lost_mb": round(total_size_lost / (1024 * 1024), 2),
            "with_gps_count": len(with_gps),
            "with_dates_count": len(with_dates),
            "by_extension": dict(by_ext),
            "critical_deletions": with_gps[:20],  # удалённые с GPS — это серьёзно
            "all_deleted_paths": [e.get("path") for e in deletions][:50],
        }

    def _analyze_additions(self) -> Dict[str, Any]:
        additions = [e for e in self.diff_entries if e.get("status") == "ADDED"]
        total_size_added = 0
        by_ext: Dict[str, int] = defaultdict(int)
        suspicious = []

        for e in additions:
            new_f = self.new_files.get(e.get("path", ""), {})
            total_size_added += new_f.get("size_bytes", 0)
            ext = new_f.get("declared_ext", ".unknown")
            by_ext[ext] += 1
            if new_f.get("match_status") == "MISMATCH":
                suspicious.append({
                    "path": e.get("path"),
                    "declared": new_f.get("declared_ext"),
                    "real": new_f.get("real_mime"),
                })

        return {
            "count": len(additions),
            "total_size_added_mb": round(total_size_added / (1024 * 1024), 2),
            "by_extension": dict(by_ext),
            "suspicious": suspicious,
        }

    def _analyze_content_modifications(self) -> Dict[str, Any]:
        mods = [e for e in self.diff_entries if e.get("status") == "CONTENT_MODIFIED"]
        details = []
        total_delta = 0
        for e in mods:
            delta = e.get("details", {}).get("size_delta", 0)
            total_delta += delta
            details.append({
                "path": e.get("path"),
                "size_delta": delta,
                "old_hash": e.get("details", {}).get("old_hash", "")[:16],
                "new_hash": e.get("details", {}).get("new_hash", "")[:16],
            })
        return {
            "count": len(mods),
            "total_size_delta_bytes": total_delta,
            "details": details,
        }

    def _analyze_metadata_modifications(self) -> Dict[str, Any]:
        """Анализ изменений метаданных (при том же контенте)."""
        mods = [e for e in self.diff_entries if e.get("status") == "META_MODIFIED"]
        field_changes: Dict[str, int] = defaultdict(int)
        details = []

        for e in mods:
            path = e.get("path", "")
            old_f = self.old_files.get(path, {})
            new_f = self.new_files.get(path, {})
            old_meta = old_f.get("metadata", {})
            new_meta = new_f.get("metadata", {})

            changed_fields = []
            all_keys = set(old_meta.keys()) | set(new_meta.keys())
            for key in all_keys:
                old_val = old_meta.get(key)
                new_val = new_meta.get(key)
                if old_val != new_val:
                    field_changes[key] += 1
                    changed_fields.append({
                        "field": key,
                        "old": str(old_val)[:60] if old_val else "(missing)",
                        "new": str(new_val)[:60] if new_val else "(missing)",
                    })
            details.append({
                "path": path,
                "fields_changed": len(changed_fields),
                "changes": changed_fields[:5],  # топ-5 изменений
            })

        return {
            "count": len(mods),
            "top_changed_fields": dict(sorted(field_changes.items(),
                                              key=lambda x: x[1], reverse=True)[:10]),
            "details": details[:20],
        }

    def _analyze_moves(self) -> Dict[str, Any]:
        moves = [e for e in self.diff_entries if e.get("status") == "MOVED"]
        details = []
        by_directory_change: Dict[str, int] = defaultdict(int)

        for e in moves:
            from_path = e.get("details", {}).get("from", "")
            to_path = e.get("details", {}).get("to", "")
            from_dir = "/".join(from_path.split("/")[:-1]) or "(root)"
            to_dir = "/".join(to_path.split("/")[:-1]) or "(root)"
            if from_dir != to_dir:
                by_directory_change[f"{from_dir} → {to_dir}"] += 1
            details.append({
                "from": from_path,
                "to": to_path,
                "cross_directory": from_dir != to_dir,
            })

        return {
            "count": len(moves),
            "cross_directory_moves": len(moves) - sum(1 for d in details if not d["cross_directory"]),
            "directory_transitions": dict(by_directory_change),
            "details": details[:30],
        }

    def _critical_findings(self) -> List[Dict[str, str]]:
        """Форензик-находки, требующие внимания эксперта."""
        findings: List[Dict[str, str]] = []

        # 1. Массовое удаление (антифорензика)
        deleted_count = sum(1 for e in self.diff_entries if e.get("status") == "DELETED")
        if deleted_count >= 10:
            findings.append({
                "severity": "HIGH",
                "type": "mass_deletion",
                "detail": f"{deleted_count} files deleted — possible anti-forensics",
            })

        # 2. Удаление файлов с GPS (скрытие местоположения)
        deletions_with_gps = [e for e in self.diff_entries
                              if e.get("status") == "DELETED" and
                              any("GPS" in k for k in self.old_files.get(e.get("path", {}), {}).get("metadata", {}))]
        if deletions_with_gps:
            findings.append({
                "severity": "HIGH",
                "type": "gps_evidence_deleted",
                "detail": f"{len(deletions_with_gps)} files with GPS data deleted",
                "paths": [e.get("path") for e in deletions_with_gps[:5]],
            })

        # 3. Подмена метаданных (DateTimeOriginal изменён)
        for e in self.diff_entries:
            if e.get("status") == "META_MODIFIED":
                path = e.get("path", "")
                old_meta = self.old_files.get(path, {}).get("metadata", {})
                new_meta = self.new_files.get(path, {}).get("metadata", {})
                old_date = old_meta.get("EXIF DateTimeOriginal")
                new_date = new_meta.get("EXIF DateTimeOriginal")
                if old_date and new_date and old_date != new_date:
                    findings.append({
                        "severity": "HIGH",
                        "type": "datetime_tampering",
                        "path": path,
                        "detail": f"DateTimeOriginal: {old_date} → {new_date}",
                    })

        # 4. Подозрительные новые файлы
        for e in self.diff_entries:
            if e.get("status") == "ADDED":
                new_f = self.new_files.get(e.get("path", ""), {})
                if new_f.get("match_status") == "MISMATCH":
                    findings.append({
                        "severity": "HIGH",
                        "type": "new_spoofed_file",
                        "path": e.get("path"),
                        "detail": f"declared={new_f.get('declared_ext')}, real={new_f.get('real_mime')}",
                    })

        # 5. Многократная модификация метаданных
        meta_mod_count = sum(1 for e in self.diff_entries if e.get("status") == "META_MODIFIED")
        if meta_mod_count >= 5:
            findings.append({
                "severity": "MEDIUM",
                "type": "bulk_metadata_tampering",
                "detail": f"{meta_mod_count} files had metadata modified",
            })

        # Сортировка
        order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        findings.sort(key=lambda x: order.get(x["severity"], 99))
        return findings