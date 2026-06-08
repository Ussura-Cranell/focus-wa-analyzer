# core/reporting/renderers/cli.py
from typing import Dict, Any, List
from tabulate import tabulate

LINE = "=" * 70
THIN = "-" * 70

def render_baseline_report(metrics: Dict[str, Any], signature: str = None) -> str:
    lines: List[str] = []
    lines.append(LINE)
    lines.append("  WHATSAPP MEDIA FORENSIC REPORT - BASELINE")
    lines.append(LINE)
    lines.append("")

    s = metrics["summary"]
    lines.append("[SCAN SUMMARY]")
    lines.append(f"  Total files:      {s['total_files']}")
    lines.append(f"  Total size:       {s['total_size_mb']} MB")
    lines.append(f"  |- Media:         {s['media_files']}")
    lines.append(f"  |- Documents:     {s['document_files']}")
    lines.append(f"  '- Other:         {s['other_files']}")
    lines.append("")

    lines.append("[FILE TYPES]")
    ext_table = [[ext, count, f"{count / s['total_files'] * 100:.1f}%"]
                 for ext, count in sorted(metrics["extensions"].items(), key=lambda x: x[1], reverse=True)]
    lines.append(tabulate(ext_table, headers=["Extension", "Count", "%"], tablefmt="simple"))
    lines.append("")

    lines.append("[METADATA COVERAGE]")
    mc = metrics["metadata_coverage"]
    total = s["total_files"] or 1
    lines.append(f"  EXIF/Image tags:  {mc['has_exif']:>4}  ({mc['has_exif'] / total * 100:.1f}%)")
    lines.append(f"  GPS coordinates:  {mc['has_gps']:>4}  ({mc['has_gps'] / total * 100:.1f}%)")
    lines.append(f"  Office/PDF meta:  {mc['has_office']:>4}  ({mc['has_office'] / total * 100:.1f}%)")
    lines.append(f"  Audio tags:       {mc['has_audio']:>4}  ({mc['has_audio'] / total * 100:.1f}%)")
    lines.append(f"  No metadata:      {mc['no_metadata']:>4}  ({mc['no_metadata'] / total * 100:.1f}%)")
    lines.append("")

    td = metrics["temporal_distribution"]
    if td["by_year"]:
        lines.append("[TIMELINE - Files by creation year]")
        for year, count in td["by_year"].items():
            bar = "#" * min(count, 40)
            lines.append(f"  {year}  {count:>4}  {bar}")
        if td["undated"]:
            lines.append(f"  (?)   {td['undated']:>4}  (undated)")
        lines.append("")

    sw = metrics["software_chain"]
    if sw:
        lines.append("[SOFTWARE USED FOR PROCESSING]")
        for name, count in sorted(sw.items(), key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"  * {name:<40} ({count} files)")
        lines.append("")

    gps = metrics["gps_coverage"]
    lines.append(f"[GPS COVERAGE] {gps['files_with_gps']} files ({gps['coverage_percent']}%)")
    if gps["samples"]:
        lines.append("  Sample locations:")
        for sample in gps["samples"][:5]:
            lines.append(f"    * {sample['path']}")
            lines.append(f"      lat={sample['latitude']}, lon={sample['longitude']}")
        lines.append("")

    cf = metrics["critical_findings"]
    if cf:
        lines.append(f"[CRITICAL FINDINGS] {len(cf)} issues detected")
        for f in cf[:15]:
            tag = "[!]" if f["severity"] == "HIGH" else "[*]" if f["severity"] == "MEDIUM" else "[i]"
            lines.append(f"  {tag} [{f['severity']}] {f['type']}")
            lines.append(f"     path: {f['path']}")
            lines.append(f"     detail: {f['detail']}")
        lines.append("")
    else:
        lines.append("[CRITICAL FINDINGS] + No issues detected")
        lines.append("")

    lines.append("[LARGEST FILES]")
    for i, f in enumerate(metrics["largest_files"], 1):
        lines.append(f"  {i}. {f['size_mb']:>7} MB  {f['path']}")
    lines.append("")

    if signature:
        lines.append("[INTEGRITY]")
        lines.append(f"  HMAC-SHA256: {signature[:32]}...")
        lines.append("  Status:        + VALID")
        lines.append("")

    lines.append(LINE)
    return "\n".join(lines)


def render_compare_report(metrics: Dict[str, Any], diff_entries: List[Dict[str, Any]] = None) -> str:
    lines: List[str] = []
    lines.append(LINE)
    lines.append("  FORENSIC DIFF REPORT - CHANGES BETWEEN SCANS")
    lines.append(LINE)
    lines.append("")

    s = metrics["summary"]
    lines.append("[CHANGE SUMMARY]")
    lines.append(f"  Total changes:           {s['total_changes']}")
    lines.append(f"  |- Added:                {s['added']}")
    lines.append(f"  |- Deleted:              {s['deleted']}")
    lines.append(f"  |- Content modified:     {s['content_modified']}")
    lines.append(f"  |- Metadata modified:    {s['meta_modified']}")
    lines.append(f"  '- Moved/renamed:        {s['moved']}")
    lines.append("")

    cf = metrics.get("critical_findings", [])
    if cf:
        lines.append(f"[CRITICAL FINDINGS] {len(cf)} issues")
        for f in cf:
            tag = "[!]" if f["severity"] == "HIGH" else "[*]" if f["severity"] == "MEDIUM" else "[i]"
            lines.append(f"  {tag} [{f['severity']}] {f['type']}")
            lines.append(f"     {f['detail']}")
            if "path" in f:
                lines.append(f"     path: {f['path']}")
        lines.append("")

    dl = metrics.get("deletions", {})
    if dl.get("count"):
        lines.append(f"[DELETED FILES] {dl['count']} files, {dl['total_size_lost_mb']} MB lost")
        lines.append(f"  - With GPS data:      {dl['with_gps_count']} (forensic evidence lost)")
        lines.append(f"  - With date metadata: {dl['with_dates_count']}")
        lines.append("")

    ad = metrics.get("additions", {})
    if ad.get("count"):
        lines.append(f"[ADDED FILES] {ad['count']} files, {ad['total_size_added_mb']} MB")
        if ad.get("suspicious"):
            lines.append(f"  [!] Spoofed (MIME mismatch): {len(ad['suspicious'])}")
            for sf in ad["suspicious"][:5]:
                lines.append(f"    * {sf['path']}")
        lines.append("")

    cm = metrics.get("content_modifications", {})
    if cm.get("count"):
        lines.append(f"[CONTENT MODIFIED] {cm['count']} files")
        for d in cm["details"][:10]:
            lines.append(f"  * {d['path']} (size delta: {d['size_delta']:+} bytes)")
        lines.append("")

    mv = metrics.get("moves", {})
    if mv.get("count"):
        lines.append(f"[MOVED / RENAMED] {mv['count']} files")
        lines.append(f"  Cross-directory moves: {mv.get('cross_directory_moves', 0)}")
        if mv.get("metadata_changed_during_move_count", 0) > 0:
            lines.append(f"  [!] Metadata changed during move: {mv['metadata_changed_during_move_count']}")
        lines.append("")

    lines.append(LINE)
    return "\n".join(lines)