from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

class BaseSource(ABC):
    @abstractmethod
    def scan(self, root: Path | None = None) -> Iterator[Path]:
        pass