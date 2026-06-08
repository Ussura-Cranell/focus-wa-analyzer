# tests/test_adb_unit.py
import pytest
from unittest.mock import patch, MagicMock
from sources.adb import AdbSource
from pathlib import Path

def test_adb_connection_success():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="List of devices attached\n123\tdevice\n", 
            returncode=0
        )
        source = AdbSource(device_id="123")
        assert source.device == "123"

def test_list_remote_files():
    # 🔧 Мок должен быть внутри модуля adb, чтобы перехватить вызовы из __init__
    with patch("sources.adb.subprocess.run") as mock_run:
        # Первый вызов: _verify_connection -> adb devices
        # Второй вызов: _list_remote_files -> adb shell find
        mock_run.side_effect = [
            MagicMock(stdout="List of devices attached\n123\tdevice\n", returncode=0),  # devices
            MagicMock(stdout="/sdcard/WhatsApp/Media/test.jpg\n", returncode=0),        # find
        ]
        source = AdbSource()
        files = source._list_remote_files()
        assert len(files) == 1
        assert "test.jpg" in files[0]