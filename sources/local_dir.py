# sources/local_dir.py
from pathlib import Path
from typing import Iterator
import config
from .base import BaseSource

class LocalDirSource(BaseSource):
    def scan(self, root: Path | None = None) -> Iterator[Path]:
        if not root or not root.is_dir():
            raise ValueError(f"Invalid directory: {root}")
            
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.name.startswith("."):
                continue
            if p.suffix.lower() in config.ALLOWED_EXTS:
                yield p