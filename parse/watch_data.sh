#!/bin/bash

PROJECT_DIR="/home/shad/app/ai360_osv_insights"
DATA_DIR="$PROJECT_DIR/data"
SCRIPT_PATH="$PROJECT_DIR/parse/data_base.py"
PYTHON_EXEC="$PROJECT_DIR/venv/bin/python"

cd "$PROJECT_DIR"

echo "Мониторинг папки data запущен (интервал 30 сек)..."

while true; do
    # Быстрая проверка: есть ли хоть один файл .json в папке data
    if find "$DATA_DIR" -maxdepth 1 -name "*.json" -print -quit | grep -q .; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Найдены новые JSON файлы. Запуск парсера..."

        # Запускаем питоновский скрипт через абсолютный путь venv
        $PYTHON_EXEC $SCRIPT_PATH
    fi

    sleep 30
done
