import subprocess
import tempfile
import logging
from pathlib import Path
from typing import Iterator
from .base import BaseSource
import config

logger = logging.getLogger(__name__)

class AdbSource(BaseSource):
    DEFAULT_PATH = "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media"
    FALLBACK_PATH = "/storage/emulated/0/WhatsApp/Media"

    def __init__(self, device_id: str | None = None, remote_path: str | None = None, keep_temp: bool = False):
        self.device = device_id
        self.remote_path = (remote_path or self.DEFAULT_PATH).rstrip("/")
        self._adb_cmd = ["adb"]
        if self.device:
            self._adb_cmd += ["-s", self.device]
        self._verify_connection()
        self.keep_temp = keep_temp

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        full_cmd = self._adb_cmd + cmd
        try:
            return subprocess.run(full_cmd, capture_output=True, text=True, check=check)
        except subprocess.CalledProcessError as e:
            if check:
                raise
            return e

    def _verify_connection(self):
        try:
            res = subprocess.run(self._adb_cmd + ["devices"], capture_output=True, text=True)
            devices = [l.split("\t") for l in res.stdout.strip().splitlines()[1:] if l.strip()]
            if not any(d[1] == "device" for d in devices):
                raise RuntimeError("No ADB device connected. Enable USB Debugging and authorize PC.")
        except FileNotFoundError:
            raise RuntimeError("ADB not found. Install Android Platform Tools (`sudo apt install adb`).")

    def _list_remote_files(self) -> list[str]:
        logger.info(f"Scanning remote: {self.remote_path}")
        try:
            res = self._run(["shell", "find", self.remote_path, "-type", "f"], check=False)
            if not res.stdout.strip():
                logger.warning("Primary path empty, switching to fallback...")
                self.remote_path = self.FALLBACK_PATH.rstrip("/")
                res = self._run(["shell", "find", self.remote_path, "-type", "f"])
        except Exception as e:
            logger.warning(f"Primary path failed ({e}), trying fallback...")
            res = self._run(["shell", "find", self.FALLBACK_PATH.rstrip("/"), "-type", "f"])

        files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
        allowed = config.ALLOWED_EXTS
        return [f for f in files if f.lower().endswith(tuple(allowed))]

    def scan(self, root: Path | None = None) -> Iterator[Path]:
        tmp_base = Path(tempfile.mkdtemp(prefix="wa_adb_"))
        try:
            remote_files = self._list_remote_files()
            logger.info(f"Found {len(remote_files)} candidates. Pulling valid files...")

            pulled_count = 0
            for remote_path in remote_files:
                try:
                    rel = Path(remote_path).relative_to(self.remote_path)
                except ValueError:
                    rel = Path(remote_path[len(self.remote_path):].lstrip("/"))
                
                local_dir = tmp_base / rel.parent
                local_dir.mkdir(parents=True, exist_ok=True)
                local_file = local_dir / rel.name

                try:
                    stat_res = self._run(["shell", "stat", "-c", "%s %F", remote_path], check=False)
                    if stat_res.returncode == 0:
                        parts = stat_res.stdout.strip().split(maxsplit=1)
                        if len(parts) == 2 and (int(parts[0]) == 0 or "symbolic link" in parts[1]):
                            continue
                except Exception:
                    pass

                pull_res = self._run(["pull", remote_path, str(local_dir)], check=False)
                if pull_res.returncode == 0 and local_file.exists() and local_file.stat().st_size > 0:
                    pulled_count += 1
                    yield local_file

            logger.info(f"Pulled {pulled_count} files. Skipping {len(remote_files) - pulled_count}.")
        finally:
            if not self.keep_temp:
                import shutil
                shutil.rmtree(tmp_base, ignore_errors=True)
            else:
                logger.info(f"Temp files preserved at: {tmp_base}")