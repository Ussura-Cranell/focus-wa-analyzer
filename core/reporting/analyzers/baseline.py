# core/reporting/analyzers/baseline.py
"""Углублённый анализ одного скана (baseline)."""
from typing import Dict, Any, List
from collections import Counter, defaultdict
from datetime import datetime


class BaselineAnalyzer:
    """Анализирует один слепок и возвращает форензик-метрики."""

    def __init__(self, files: Dict[str, Any]):
        self.files = files

    def analyze(self) -> Dict[str, Any]:
        return {
            "summary": self._summary(),
            "temporal_distribution": self._temporal_distribution(),
            "gps_coverage": self._gps_coverage(),
            "software_chain": self._software_chain(),
            "critical_findings": self._critical_findings(),
            "largest_files": self._largest_files(),
            "extensions": self._extensions(),
            "metadata_coverage": self._metadata_coverage(),
        }

    def _summary(self) -> Dict[str, Any]:
        total = len(self.files)
        total_size = sum(f.get("size_bytes", 0) for f in self.files.values())
        media_count = sum(1 for f in self.files.values() if f.get("is_media"))
        doc_count = sum(1 for f in self.files.values() if f.get("is_document"))
        return {
            "total_files": total,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "media_files": media_count,
            "document_files": doc_count,
            "other_files": total - media_count - doc_count,
        }

    def _extensions(self) -> Dict[str, int]:
        return dict(Counter(f.get("declared_ext", ".unknown") for f in self.files.values()))

    def _metadata_coverage(self) -> Dict[str, int]:
        total = len(self.files)
        has_exif = sum(1 for f in self.files.values()
                       if any(k.startswith(("EXIF", "Image", "GPS")) for k in f.get("metadata", {})))
        has_gps = sum(1 for f in self.files.values()
                      if any("GPS" in k for k in f.get("metadata", {})))
        has_office = sum(1 for f in self.files.values()
                         if any(k.startswith(("PDF", "Office")) for k in f.get("metadata", {})))
        has_audio = sum(1 for f in self.files.values()
                        if any(k.startswith("Audio") for k in f.get("metadata", {})))
        return {
            "has_exif": has_exif,
            "has_gps": has_gps,
            "has_office": has_office,
            "has_audio": has_audio,
            "no_metadata": total - has_exif - has_office - has_audio,
        }

    def _temporal_distribution(self) -> Dict[str, Any]:
        """Распределяет файлы по годам создания (из EXIF/PDF/Office)."""
        by_year: Dict[str, int] = defaultdict(int)
        undated = 0
        anomalies: List[Dict[str, str]] = []

        for path, f in self.files.items():
            date_found = None
            meta = f.get("metadata", {})
            for key in ("EXIF DateTimeOriginal", "Image DateTime",
                        "PDF CreationDate", "Office Created"):
                if key in meta and isinstance(meta[key], str) and meta[key]:
                    date_found = meta[key]
                    break
            if not date_found:
                undated += 1
                continue
            try:
                year = date_found[:4]
                if year.isdigit() and 1970 <= int(year) <= 2100:
                    by_year[year] += 1
                    if int(year) > datetime.now().year:
                        anomalies.append({"path": path, "date": date_found,
                                          "reason": "future_date"})
                    elif int(year) < 1990:
                        anomalies.append({"path": path, "date": date_found,
                                          "reason": "suspiciously_old"})
            except (ValueError, IndexError):
                undated += 1

        return {
            "by_year": dict(sorted(by_year.items())),
            "undated": undated,
            "anomalies": anomalies[:20],
        }

    def _gps_coverage(self) -> Dict[str, Any]:
        """Анализ GPS-покрытия."""
        with_gps = []
        for path, f in self.files.items():
            meta = f.get("metadata", {})
            lat = meta.get("GPS GPSLatitude")
            lon = meta.get("GPS GPSLongitude")
            if lat and lon:
                with_gps.append({
                    "path": path,
                    "latitude": str(lat),
                    "longitude": str(lon),
                })
        total = len(self.files)
        return {
            "files_with_gps": len(with_gps),
            "coverage_percent": round(len(with_gps) / total * 100, 1) if total else 0,
            "samples": with_gps[:10],
        }

    def _software_chain(self) -> Dict[str, int]:
        """Считает, в каком ПО обрабатывались файлы."""
        counter: Dict[str, int] = defaultdict(int)
        for f in self.files.values():
            meta = f.get("metadata", {})
            sw = meta.get("Image Software") or meta.get("EXIF Software") or meta.get("PDF Producer")
            if sw and isinstance(sw, str) and sw.strip():
                counter[sw.strip()] += 1
        return dict(counter)

    def _largest_files(self, limit: int = 5) -> List[Dict[str, Any]]:
        sorted_files = sorted(self.files.values(),
                              key=lambda x: x.get("size_bytes", 0),
                              reverse=True)[:limit]
        return [{"path": f.get("relative_path", ""),
                 "size_mb": round(f.get("size_bytes", 0) / (1024 * 1024), 2)}
                for f in sorted_files]

    def _critical_findings(self) -> List[Dict[str, str]]:
        """Находит потенциальные следы подделки/антифорензики."""
        findings: List[Dict[str, str]] = []

        for path, f in self.files.items():
            # 1. Спуфинг MIME
            if f.get("match_status") == "MISMATCH":
                findings.append({
                    "severity": "HIGH",
                    "type": "mime_mismatch",
                    "path": path,
                    "detail": f"declared={f.get('declared_ext')}, real={f.get('real_mime')}",
                })

            # 2. Подозрительные даты
            meta = f.get("metadata", {})
            date_str = meta.get("EXIF DateTimeOriginal", "")
            if isinstance(date_str, str) and date_str:
                try:
                    year = int(date_str[:4])
                    if year > datetime.now().year:
                        findings.append({
                            "severity": "MEDIUM",
                            "type": "future_date",
                            "path": path,
                            "detail": f"DateTimeOriginal={date_str}",
                        })
                except ValueError:
                    pass

            # 3. Следы редактирования ПО
            sw = meta.get("Image Software", "")
            if isinstance(sw, str) and any(tool in sw.lower()
                                           for tool in ("photoshop", "gimp", "lightroom", "paint.net")):
                findings.append({
                    "severity": "INFO",
                    "type": "edited_by_software",
                    "path": path,
                    "detail": f"software={sw}",
                })

            # 4. Файлы с нулевым размером
            if f.get("size_bytes", -1) == 0:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "zero_byte_file",
                    "path": path,
                    "detail": "size=0 bytes",
                })

        # Сортировка по критичности
        order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        findings.sort(key=lambda x: order.get(x["severity"], 99))
        return findings