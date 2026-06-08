from pathlib import Path
from tqdm import tqdm
from .models import ScanManifest
from .extractor import extract_file
from sources.base import BaseSource
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def run_scan(source: BaseSource, root: Path | None = None, strict: bool = False,
             audit_log=None) -> ScanManifest:
    """
    Сканирует файлы из источника.
    :param audit_log: опциональный AuditLogger для журналирования действий
    """
    import time
    scan_id = f"scan_{root.name if root else 'adb'}_{int(time.time() * 1000)}"
    source_root = str(root.resolve()) if root else "adb://device"

    manifest = ScanManifest(
        scan_id=scan_id,
        source_root=source_root,
        scan_timestamp="",
    )

    if audit_log:
        source_type = "local" if root else "adb"
        audit_log.log_scan_start(source_type, source_root)

    files_iter = source.scan(root)

    for fpath in tqdm(files_iter, desc="Scanning files", unit="file"):
        try:
            record = extract_file(fpath, root if root else fpath.parent.parent, strict)
            manifest.files[record.relative_path] = record
            if audit_log:
                audit_log.log_file_processed(
                    record.relative_path,
                    record.hash_content,
                    record.hash_meta,
                )
        except Exception as e:
            manifest.warnings.append(f"{fpath}: {str(e)}")
            logger.warning(f"Skipping {fpath}: {e}")

    if manifest.files:
        first = next(iter(manifest.files.values()))
        manifest.scan_timestamp = first.scan_timestamp

    if audit_log:
        audit_log.log_scan_complete(len(manifest.files), len(manifest.warnings))

    return manifest