#!/usr/bin/env python3
"""
полный цикл обновления osv: скачивание zip, распаковка, обработка json,
запись в бд, очистка временных файлов
запускается на VPS, код импортируется из текущего репозитория
"""
import sys
import os
import tempfile
import urllib.request
import zipfile
import shutil
from pathlib import Path
import psycopg2

from parse.data_base import process_single_file, DB_PARAMS

URLS = {
    "pypi": "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip",
    "npm": "https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip",
    "go": "https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip",
    "oss-fuzz": "https://storage.googleapis.com/osv-vulnerabilities/OSS-Fuzz/all.zip",
    "maven": "https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip",
}

def process_archive(url: str, conn):
    """скачивает архив, обрабатывает json"""
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = Path(tmpdir) / "all.zip"
        print(f"Скачивание {url} ...")
        urllib.request.urlretrieve(url, zip_path)
        print(f"Скачано: {zip_path.stat().st_size} байт")

        extract_dir = Path(tmpdir) / "extracted"
        extract_dir.mkdir()
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)

        json_files = list(extract_dir.rglob("*.json"))
        print(f"Найдено {len(json_files)} JSON-файлов.")
        cur = conn.cursor()
        for json_file in json_files:
            try:
                if process_single_file(cur, json_file):
                    conn.commit()
                else:
                    conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"  ОШИБКА в {json_file.name}: {e}")

def main():
    # какие экосистемы обрабатывать (можно через переменную окружения ECOSYSTEMS)
    ecosystems_str = os.environ.get("ECOSYSTEMS", "pypi,npm,go,oss-fuzz,maven")
    ecosystems = [e.strip() for e in ecosystems_str.split(",") if e.strip()]

    # подключаемся к базе (параметры из DB_PARAMS, которые могут читать переменные окружения)
    print("Подключение к БД...")
    try:
        conn = psycopg2.connect(**DB_PARAMS)
    except Exception as e:
        print(f"Не удалось подключиться к БД: {e}")
        sys.exit(1)
    try:
        for eco in ecosystems:
            url = URLS.get(eco)
            if not url:
                print(f"Неизвестная экосистема: {eco}, пропускаем")
                continue
            print(f"\n=== Обработка {eco} ===")
            process_archive(url, conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()