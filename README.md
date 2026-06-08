# 🔍 FOCUS — Forensic Object Capture & Unified Scan

> Инструмент для форензик-анализа метаданных медиафайлов WhatsApp с поддержкой ADB, двойным хешированием и криптографической верификацией отчётов.

---

## 📑 Оглавление

- [О проекте](#о-проекте)
- [Возможности](#возможности)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Режимы работы](#режимы-работы)
- [Управление БД](#управление-бд)
- [Примеры](#примеры)
- [Тестирование](#тестирование)
- [Разработка](#разработка)

---

## О проекте

**FOCUS** решает задачу цифровой криминалистики медиафайлов WhatsApp: извлечение, нормализация и сравнительный анализ метаданных (время съёмки, GPS-координаты) с гарантией целостности доказательств.

**Сценарии применения:**
- Расследование инцидентов ИБ
- Судебная экспертиза цифровых доказательств
- Детекция фальсификации метаданных

---

## Возможности

- **Источники**: локальные ФС, Android через ADB
- **Анализ**: определение MIME по сигнатурам, детекция спуфинга
- **Метаданные**: EXIF (время, GPS), нормализация в UTC
- **Хеширование**: двойное (`hash_content` + `hash_meta`)
- **Сравнение**: `baseline`/`compare` с детекцией `ADDED`, `DELETED`, `MOVED`, `CONTENT_MODIFIED`, `META_MODIFIED`
- **Хранение**: SQLite и JSON
- **Целостность**: HMAC-SHA256 подпись отчётов
- **Аудит**: логирование действий оператора

---

## Установка

### Требования

- Python 3.10+
- ADB (для Android)
- SQLite3 (встроен в Python)

### Шаги

```bash
git clone https://github.com/<username>/focus.git
cd focus

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### ADB (опционально)

```bash
# Ubuntu/Debian
sudo apt install android-tools-adb

# macOS
brew install android-platform-tools
```

### Проверка

```bash
python focus.py --help
```

---

## Быстрый старт

### Локальное сканирование

```bash
./focus.py --db evidence.db --mode baseline \
  --source-type local --source-dir /path/to/media \
  --db-name "Suspect_Drive" --report full --sign
```

### ADB-сканирование

```bash
adb devices

./focus.py --db evidence.db --mode baseline \
  --source-type adb --db-name "Mobile_ADB" --report baseline
```

### Сравнение

```bash
./focus.py --db evidence.db --mode compare \
  --db-ref "Suspect_Drive" --db-name "Suspect_Drive_Post" \
  --report full
```

---

## Режимы работы

### Baseline

Создаёт эталонный скан: вычисляет хеши, извлекает метаданные, сохраняет в БД/JSON.

```bash
./focus.py --db evidence.db --mode baseline \
  --source-type <local|adb> \
  [--source-dir PATH] \
  --db-name NAME \
  [--report none|baseline|full] \
  [--sign]
```

**Параметры:**

| Параметр | Описание | Обязательный |
|----------|----------|--------------|
| `--db-path` | Путь к SQLite БД | Да (для DB) |
| `--output` | Путь к JSON | Да (для JSON) |
| `--source-type` | `local` или `adb` | Нет (по умолчанию `local`) |
| `--db-name` | Имя скана в БД | Да |
| `--sign` | Подписать HMAC-SHA256 | Нет |

### Compare

Вычисляет дельту между эталоном и текущим состоянием. Если `--db-name` не существует — автоматически создаёт новый скан.

```bash
./focus.py --db evidence.db --mode compare \
  --db-ref REF_NAME --db-name NEW_NAME \
  [--report compare|full]
```

**Детектируемые изменения:**

| Статус | Условие | Интерпретация |
|--------|---------|---------------|
| `CONTENT_MODIFIED` | `hash_content` изменился | Файл отредактирован |
| `META_MODIFIED` | `hash_content` совпадает, `hash_meta` нет | Подделаны метаданные |
| `MOVED` | Хеш совпадает с удалённым | Файл перемещён |
| `ADDED` | Новый файл без аналога | Добавлен после baseline |
| `DELETED` | Файл из эталона отсутствует | Удалён |

### View

Загружает скан из БД без повторного сканирования.

```bash
./focus.py --db evidence.db --mode view \
  --db-name NAME --report full
```

---

## Управление БД

### Список сканов

```bash
./focus.py --db evidence.db --db-list
```

**Вывод:**
```
+------------------+--------+-------+---------------------+------+
| Name             | Source | Files | Timestamp           | Sign |
+==================+========+=======+=====================+======+
| Suspect_Drive    | local  |   342 | 2026-06-01T18:01:48 | ✓    |
| Mobile_ADB       | adb    |   316 | 2026-06-01T19:15:22 | ✓    |
+------------------+--------+-------+---------------------+------+
```

### Метаданные скана

```bash
./focus.py --db evidence.db --db-show Suspect_Drive
```

### Верификация подписи

```bash
./focus.py --db evidence.db --db-verify Suspect_Drive
# [+] Signature VALID for 'Suspect_Drive'
```

### Переименование

```bash
./focus.py --db evidence.db --db-rename OLD_NAME --db-new-name NEW_NAME
```

### Удаление

```bash
./focus.py --db evidence.db --db-delete Suspect_Drive
```

### Экспорт/Импорт

```bash
# Экспорт
./focus.py --db evidence.db --db-export Suspect_Drive --output exported.json

# Импорт
./focus.py --db evidence.db --db-import imported.json --db-name Imported_Scan
```

---

## Примеры

### Полный форензик-цикл

```bash
# Шаг 1: Базовый скан
./focus.py --db case.db --mode baseline \
  --source-type local --source-dir /mnt/evidence \
  --db-name "Evidence_Initial" --report full --sign

# Шаг 2: Повторное сканирование через неделю
./focus.py --db case.db --mode compare \
  --db-ref "Evidence_Initial" --db-name "Evidence_Week1" \
  --report full --sign
```

### ADB с сохранением временных файлов

```bash
./focus.py --db evidence.db --mode baseline \
  --source-type adb \
  --adb-device 119582543P104506 \
  --db-name "WhatsApp_ADB" \
  --keep-temp --report baseline
```

### JSON-режим (без SQLite)

```bash
# Создание эталона
./focus.py --mode baseline \
  --source-type local --source-dir ./media \
  --output baseline.json --sign

# Сравнение
./focus.py --mode compare \
  --source-type local --source-dir ./media \
  --reference baseline.json \
  --output diff.json --report full
```

---

## Тестирование

```bash
# Все тесты
python -m pytest tests/ -v

# Только форензик
python -m pytest tests/test_forensic.py -v

# Только ADB
python -m pytest tests/test_adb_unit.py tests/test_adb_integration.py -v

# С покрытием
python -m pytest tests/ --cov=core --cov=sources --cov-report=term-missing
```

**Структура тестов:**

```
tests/
├── test_forensic.py          # спуфинг, тамперинг
├── test_adb_unit.py          # моки ADB
├── test_adb_integration.py   # эмуляция ADB
── test_extractor.py          # извлечение метаданных
├── test_parsers.py           # парсеры форматов
├── test_storage.py           # SQLite/JSON
├── test_audit.py             # аудит-лог
├── test_analyzers.py         # baseline/compare
├── test_assets/              # тестовые файлы
│   ├── baseline/             # эталонные JPEG
│   ├── edge_cases/           # битые заголовки
│   ├── forensic/             # спуфинг, тамперинг
│   └── ...
└── golden/                   # эталонные JSON
```

---

## Разработка

### Структура проекта

```
focus/
── focus.py                   # CLI
├── config.py                 # конфигурация, HMAC
├── core/
│   ├── models.py             # FileRecord, Manifest
│   ├── extractor.py          # извлечение метаданных
│   ├── profiler.py           # спуфинг-детекция
│   ├── pipeline.py           # оркестратор
│   ├── storage.py            # SQLite/JSON
│   ├── audit.py              # аудит
│   ├── parsers/              # парсеры форматов
│   └── reporting/            # отчёты
├── sources/
│   ├── base.py               # BaseSource
│   ├── local_dir.py          # локальный источник
│   └── adb.py                # ADB-источник
└── tests/
```

## Лицензия

MIT. См. файл `LICENSE`.
