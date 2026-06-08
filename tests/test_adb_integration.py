import tempfile
import shutil
from pathlib import Path
from core.pipeline import run_scan
from sources.local_dir import LocalDirSource

def test_adb_like_scan_with_temp():
    """
    Эмулирует ADB-сканирование:
    1. Создаёт temp-директорию с файлами
    2. Запускает пайплайн
    3. Проверяет результат
    """
    # 🔧 Находим корень проекта относительно этого файла теста
    project_root = Path(__file__).resolve().parents[1]
    assets_dir = project_root / "tests" / "test_assets"
    
    # 🔧 Динамически ищем любой .jpg в ассетах (не зависит от имён файлов)
    src = None
    for p in assets_dir.rglob("*.jpg"):
        if p.is_file():
            src = p
            break
            
    assert src is not None, f"No .jpg files found in {assets_dir}"
    
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp).resolve()
        shutil.copy(src, tmp_path / "test_photo.jpg")
        
        # Запускаем сканирование
        source = LocalDirSource()
        manifest = run_scan(source, tmp_path)
        
        # Проверяем результат
        assert len(manifest.files) >= 1, f"Expected >=1 files, got {len(manifest.files)}"
        record = list(manifest.files.values())[0]
        assert record.hash_content, "Hash content is missing"
        assert record.is_media, "File not recognized as media"