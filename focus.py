#!/usr/bin/env python3
"""
WhatsApp Media Forensic Analyzer
Профессиональный инструмент для форензик-анализа медиафайлов.
"""
import argparse
import json
import sys
import os
import logging
from pathlib import Path
from dataclasses import asdict
from tabulate import tabulate

from core.pipeline import run_scan
from core.models import DiffEntry, ScanManifest
from core.audit import AuditLogger
from core.storage import SQLiteStorage, JsonStorage
from core.reporting.metrics import calculate_baseline_metrics, calculate_compare_metrics
from core.reporting.renderers.cli import render_baseline_report, render_compare_report
from sources.local_dir import LocalDirSource
from sources.adb import AdbSource
import config


def save_json(data, path: str, sign: bool = False):
    if hasattr(data, "__dict__"):
        data = asdict(data)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    print(f"[+] Output saved to {path}")
    
    if sign and isinstance(data, dict):
        signature = config.sign_report(data)
        data["_signature"] = signature
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        print(f"[+] Report signed: {signature[:16]}...")


def compute_diff(old: dict, new: dict) -> list:
    old_files = old.get("files", {})
    new_files = new.get("files", {})
    old_paths = set(old_files.keys())
    new_paths = set(new_files.keys())

    deleted = old_paths - new_paths
    added = new_paths - old_paths
    common = old_paths & new_paths

    diff_entries = []
    deleted_hashes = {old_files[p]["hash_content"]: p for p in deleted}

    for p in common:
        o, n = old_files[p], new_files[p]
        if o["hash_content"] != n["hash_content"]:
            diff_entries.append(DiffEntry(p, "CONTENT_MODIFIED", {
                "old_hash": o["hash_content"],
                "new_hash": n["hash_content"],
                "size_delta": n["size_bytes"] - o["size_bytes"],
            }))
        elif o.get("hash_meta") != n.get("hash_meta"):
            diff_entries.append(DiffEntry(p, "META_MODIFIED", {}))

    for p in added:
        rec = new_files[p]
        if rec["hash_content"] in deleted_hashes:
            old_p = deleted_hashes.pop(rec["hash_content"])
            diff_entries.append(DiffEntry(p, "MOVED", {"from": old_p, "to": p}))
        else:
            diff_entries.append(DiffEntry(p, "ADDED", {"hash": rec["hash_content"]}))

    for old_p in deleted_hashes.values():
        diff_entries.append(DiffEntry(old_p, "DELETED", {
            "old_hash": old_files[old_p]["hash_content"],
        }))

    return diff_entries


def main():
    
    parser = argparse.ArgumentParser(
        description="FOCUS: Forensic Object Capture & Unified Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    EXAMPLES:
      [Unified Capture & Baseline]
      focus --db evidence.db --mode baseline --source-type local --source-dir /media --db-name "Suspect_Drive" --report full --sign
      focus --db evidence.db --mode baseline --source-type adb --db-name "Mobile_Device_ADB"
      
      [Unified Diff & View]
      focus --db evidence.db --mode view --db-name "Suspect_Drive" --report full
      focus --db evidence.db --mode compare --db-ref "Suspect_Drive" --db-name "Suspect_Drive_Post_Incident" --report full
    """
    )

    # 1. General Options
    general_grp = parser.add_argument_group("General Options")
    general_grp.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    general_grp.add_argument("--strict", action="store_true", help="Enable strict spoof detection")
    general_grp.add_argument("--keep-temp", action="store_true", help="Keep temporary ADB files after scan")

    # 2. Storage Selection
    storage_grp = parser.add_argument_group("Storage Selection (Choose One)")
    storage_grp.add_argument("--db-path", metavar="PATH", help="Path to SQLite database (Enables DB Mode)")
    storage_grp.add_argument("--output", metavar="FILE", help="Path to output JSON file (Enables JSON Mode)")

    # 3. Scan Source & Operation
    scan_grp = parser.add_argument_group("Scan Source & Operation")
    scan_grp.add_argument("--mode", choices=["baseline", "compare", "view"], default="baseline", 
                          help="Operation mode: 'baseline' (scan), 'compare' (diff), or 'view' (load from DB)")
    scan_grp.add_argument("--source-type", choices=["local", "adb"], default="local", help="Data source type")
    scan_grp.add_argument("--source-dir", metavar="PATH", help="Path to local directory (for local source)")
    scan_grp.add_argument("--adb-device", metavar="ID", help="ADB device ID (for adb source)")
    scan_grp.add_argument("--adb-path", metavar="PATH", help="Remote WhatsApp media path (for adb source)")

    # 4. SQLite DB Management
    db_grp = parser.add_argument_group("SQLite DB Management (Requires --db-path)")
    db_grp.add_argument("--db-name", metavar="NAME", help="Name for the scan in DB")
    db_grp.add_argument("--db-list", action="store_true", help="List all scans in the database")
    db_grp.add_argument("--db-show", metavar="NAME", help="Show metadata of a specific scan in DB")
    db_grp.add_argument("--db-verify", metavar="NAME", help="Verify HMAC signature of a scan in DB")
    db_grp.add_argument("--db-rename", metavar="OLD", help="Old name of scan to rename")
    db_grp.add_argument("--db-new-name", metavar="NEW", help="New name for --db-rename")
    db_grp.add_argument("--db-delete", metavar="NAME", help="Delete a scan from DB")
    db_grp.add_argument("--db-export", metavar="NAME", help="Export a scan from DB to JSON (requires --output)")
    db_grp.add_argument("--db-import", metavar="JSON_FILE", help="Import a JSON file into DB (requires --db-name)")

    # 5. Comparison & Reporting
    compare_grp = parser.add_argument_group("Comparison & Reporting")
    compare_grp.add_argument("--reference", metavar="FILE", help="Path to previous JSON scan (for JSON mode)")
    compare_grp.add_argument("--db-ref", metavar="NAME", help="Name of reference scan in DB (for DB mode compare)")
    compare_grp.add_argument("--report", choices=["none", "baseline", "compare", "full"], default="none", 
                             help="Generate CLI report summary")
    compare_grp.add_argument("--sign", action="store_true", help="Sign output with HMAC-SHA256")
    compare_grp.add_argument("--audit-log", metavar="FILE", help="Path to audit log file")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s", force=True)

    db_path = Path(args.db_path) if args.db_path else None
    storage = SQLiteStorage(db_path) if db_path else None

    # =========================================================================
    # DB MANAGEMENT COMMANDS (Exit after execution)
    # =========================================================================
    if args.db_list:
        if not storage:
            print("[!] --db-list requires --db-path", file=sys.stderr)
            sys.exit(1)
        scans = storage.list_scans()
        if not scans:
            print("[*] No scans in database.")
        else:
            table = [[s["name"], s.get("source_type", ""), s.get("total_files", 0), 
                      (s.get("scan_timestamp") or "")[:19], "✓" if s.get("signature") else ""] 
                     for s in scans]
            print(tabulate(table, headers=["Name", "Source", "Files", "Timestamp", "Sign"], tablefmt="grid"))
        sys.exit(0)

    if args.db_show:
        if not storage:
            print("[!] --db-show requires --db-path", file=sys.stderr)
            sys.exit(1)
        meta = storage.get_scan_meta(args.db_show)
        if not meta:
            print(f"[!] Scan '{args.db_show}' not found", file=sys.stderr)
            sys.exit(1)
        for k, v in meta.items():
            print(f"  {k}: {v}")
        sys.exit(0)

    if args.db_verify:
        if not storage:
            print("[!] --db-verify requires --db-path", file=sys.stderr)
            sys.exit(1)
        result = storage.verify_signature(args.db_verify)
        if not result["exists"]:
            print(f"[!] Scan '{args.db_verify}' not found", file=sys.stderr)
            sys.exit(1)
        if not result["has_signature"]:
            print(f"[*] Scan '{args.db_verify}' has no signature")
        elif result["valid"]:
            print(f"[+] Signature VALID for '{args.db_verify}'")
        else:
            print(f"[!] Signature INVALID for '{args.db_verify}'")
            sys.exit(1)
        sys.exit(0)

    if args.db_rename:
        if not storage or not args.db_new_name:
            print("[!] --db-rename requires --db-path and --db-new-name", file=sys.stderr)
            sys.exit(1)
        if storage.rename_scan(args.db_rename, args.db_new_name):
            print(f"[+] Renamed: {args.db_rename} -> {args.db_new_name}")
        else:
            print(f"[!] Scan '{args.db_rename}' not found", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if args.db_delete:
        if not storage:
            print("[!] --db-delete requires --db-path", file=sys.stderr)
            sys.exit(1)
        if storage.delete_scan(args.db_delete):
            print(f"[+] Deleted: {args.db_delete}")
        else:
            print(f"[!] Scan '{args.db_delete}' not found", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if args.db_export:
        if not storage or not args.output:
            print("[!] --db-export requires --db-path and --output", file=sys.stderr)
            sys.exit(1)
        out_path = storage.export_to_json(args.db_export, Path(args.output))
        print(f"[+] Exported to {out_path}")
        sys.exit(0)

    if args.db_import:
        if not storage or not args.db_name:
            print("[!] --db-import requires --db-path and --db-name", file=sys.stderr)
            sys.exit(1)
        ref = storage.import_from_json(Path(args.db_import), args.db_name)
        print(f"[+] Imported {args.db_import} as '{args.db_name}' ({ref})")
        sys.exit(0)

    # =========================================================================
    # MODE: VIEW (Load from DB and Report ONLY)
    # =========================================================================
    if args.mode == "view":
        if not storage or not args.db_name:
            print("[!] --mode view requires --db-path and --db-name", file=sys.stderr)
            sys.exit(1)
        
        try:
            manifest = storage.load_manifest(args.db_name)
            meta = storage.get_scan_meta(args.db_name)
            
            files_dict = {k: v.__dict__ for k, v in manifest.files.items()}
            metrics = calculate_baseline_metrics(files_dict)
            
            if args.report in ["baseline", "full"]:
                print("\n" + render_baseline_report(metrics, meta.get("signature")))
        except FileNotFoundError:
            print(f"[!] Scan '{args.db_name}' not found in {args.db_path}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # =========================================================================
    # MODE: BASELINE / COMPARE (Requires Source or Reference)
    # =========================================================================
    if not args.output and not db_path:
        print("[!] Either --db-path or --output is required", file=sys.stderr)
        sys.exit(1)

    audit_logger = None
    if args.audit_log:
        audit_logger = AuditLogger(
            log_path=Path(args.audit_log),
            operator=os.getenv("WA_OPERATOR", "anonymous"),
        )

    # --- Determine Source ---
    if args.mode == "baseline":
        if args.source_type == "local":
            if not args.source_dir:
                print("[!] --source-dir is required for local source", file=sys.stderr)
                sys.exit(1)
            root = Path(args.source_dir).resolve()
            source = LocalDirSource()
            scan_label = str(root)
        else:
            root = None
            source = AdbSource(device_id=args.adb_device, remote_path=args.adb_path, keep_temp=args.keep_temp)
            scan_label = "adb://device"

        print(f"[*] Scanning: {scan_label}")
        manifest = run_scan(source, root, args.strict, audit_log=audit_logger)

        # Save
        if storage and args.db_name:
            signature = config.sign_report(asdict(manifest)) if args.sign else None
            ref = storage.save_manifest(manifest, args.db_name, signature=signature)
            print(f"[+] Saved scan '{args.db_name}' -> {ref}")
            if args.sign:
                print(f"[+] Report signed")
        elif args.output:
            save_json(manifest, args.output, sign=args.sign)
        else:
            print("[!] In baseline mode, provide either --db-path + --db-name or --output", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Total files: {len(manifest.files)}")
        print(f"[*] Warnings: {len(manifest.warnings)}")

        if audit_logger:
            s = audit_logger.get_summary()
            print(f"[*] Audit log: {s['audit_log_path']} | Entries: {s['total_entries']}")

        # Report
        if args.report in ["baseline", "full"]:
            files_dict = {k: v.__dict__ for k, v in manifest.files.items()}
            metrics = calculate_baseline_metrics(files_dict)
            sig = storage.get_scan_meta(args.db_name).get("signature") if storage and args.db_name else (config.sign_report(files_dict) if args.sign else None)
            print("\n" + render_baseline_report(metrics, sig))

    # --- MODE: COMPARE ---
    elif args.mode == "compare":
        # 1. Load Old Data
        if storage and args.db_ref:
            old_manifest = storage.load_manifest(args.db_ref)
            old_data = {k: v.__dict__ for k, v in old_manifest.files.items()}
            ref_label = args.db_ref
        elif args.reference:
            with open(args.reference, "r", encoding="utf-8") as f:
                old_data = json.load(f).get("files", {})
            ref_label = args.reference
        else:
            print("[!] Compare mode requires --db-ref (with --db-path) or --reference (JSON file)", file=sys.stderr)
            sys.exit(1)

        # 2. Get New Data (Either by scanning or loading from DB)
        # 🔧 УМНАЯ ЛОГИКА: если --db-name указан, но скана нет в БД — создаём его автоматически
        scan_performed = False
        if storage and args.db_name:
            existing_meta = storage.get_scan_meta(args.db_name)
            if existing_meta:
                # Сканирование уже существует в БД — загружаем его
                new_manifest = storage.load_manifest(args.db_name)
                new_data = {k: v.__dict__ for k, v in new_manifest.files.items()}
                manifest = new_manifest
                print(f"[*] Comparing DB scans: '{ref_label}' vs '{args.db_name}'")
            else:
                # 🔧 Скана нет — выполняем сканирование и сохраняем
                print(f"[*] Scan '{args.db_name}' not found in DB. Performing new scan...")
                if args.source_type == "local":
                    root = Path(args.source_dir).resolve() if args.source_dir else None
                    source = LocalDirSource()
                else:
                    root = None
                    source = AdbSource(device_id=args.adb_device, remote_path=args.adb_path, keep_temp=args.keep_temp)
                print(f"[*] Scanning current state: {str(root) if root else 'adb://device'}")
                manifest = run_scan(source, root, args.strict, audit_log=audit_logger)
                new_data = {k: v.__dict__ for k, v in manifest.files.items()}
                
                # Сохраняем новый скан в БД
                signature = config.sign_report(asdict(manifest)) if args.sign else None
                ref = storage.save_manifest(manifest, args.db_name, signature=signature)
                print(f"[+] Saved new scan '{args.db_name}' -> {ref}")
                if args.sign:
                    print(f"[+] Report signed")
                scan_performed = True
        else:
            # Режим без БД — просто сканируем
            if args.source_type == "local":
                root = Path(args.source_dir).resolve() if args.source_dir else None
                source = LocalDirSource()
            else:
                root = None
                source = AdbSource(device_id=args.adb_device, remote_path=args.adb_path, keep_temp=args.keep_temp)
            print(f"[*] Scanning current state: {str(root) if root else 'adb://device'}")
            manifest = run_scan(source, root, args.strict, audit_log=audit_logger)
            new_data = {k: v.__dict__ for k, v in manifest.files.items()}
            if args.output:
                save_json(manifest, args.output, sign=args.sign)

        # 3. Compute Diff
        if audit_logger:
            audit_logger.log_compare_start(ref_label)
        diff = compute_diff({"files": old_data}, {"files": new_data})
        output_data = {"scan_timestamp": manifest.scan_timestamp, "diff": [asdict(d) for d in diff]}
        if args.output and not (storage and args.db_name):
            save_json(output_data, args.output, sign=args.sign)
        print(f"\n[+] Diff Summary: {len(diff)} changes")

        # Report
        if args.report in ["compare", "full"]:
            metrics = calculate_compare_metrics(old_data, new_data, [asdict(d) for d in diff])
            print("\n" + render_compare_report(metrics, [asdict(d) for d in diff]))
        elif diff:
            table_data = [[d.status, d.path, d.details.get("old_hash") or d.details.get("from", "")] for d in diff]
            print(tabulate(table_data, headers=["Status", "Path", "Old Hash/Path"], tablefmt="grid"))
        else:
            print("[*] No changes detected.")


if __name__ == "__main__":
    main()
