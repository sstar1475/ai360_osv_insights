# Используем легковесный образ Python
FROM python:3.11-slim

# Установка системных зависимостей для psycopg2 и других библиотек
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Установка рабочей директории
WORKDIR /app

# Копируем файл зависимостей
COPY requirements.txt .

# Установка зависимостей Python
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект
COPY . .

# Прокидываем порт (тот, что будет внутри контейнера)
EXPOSE 8050

# Запуск через Gunicorn
# app.app:server означает: файл app/app.py, объект server
CMD ["gunicorn", "--bind", "0.0.0.0:8050", "app.app:server", "--workers", "4", "--timeout", "120"]
