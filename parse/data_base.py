import json
import os
from pathlib import Path
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import execute_values
from osv_tools.parsing import parse_single_vulnerability

load_dotenv()

#Настройки БД из переменных окружения
DB_PARAMS = {
    "host": os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
}

#Папки
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


def process_files():
    processed_records = []
    files_to_delete = []

    #Ищем все .json в папке data
    for json_file in DATA_DIR.glob("*.json"):
        try:
            with open(json_file, encoding="utf-8") as f:
                raw_json = json.load(f)

                entry = parse_single_vulnerability(raw_json)

                if entry:
                    record = (
                        entry.get("id"),
                        entry.get("title"),
                        entry.get("description"),
                        entry.get("aliases"),
                        str(entry.get("severity")),
                        entry.get("published"),
                        entry.get("fixed"),
                        entry.get("last_affected"),
                        json.dumps(raw_json),  #Весь JSON целиком в raw_data
                        json.dumps(
                            entry.get("database_specific", {})
                        ),
                    )
                    processed_records.append(record)
                    files_to_delete.append(json_file)
        except Exception as e:
            print(f"Ошибка при обработке {json_file.name}: {e}")

    if not processed_records:
        print("Нет новых данных для загрузки")
        return

    #Заливка в БД
    query = """
        INSERT INTO vulnerabilities (
            osv_id, title, description, aliases, severity,
            published, fixed, last_affected, raw_data, database_specific
        )
        VALUES %s
        ON CONFLICT (osv_id) DO UPDATE SET
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            aliases = EXCLUDED.aliases,
            severity = EXCLUDED.severity,
            published = EXCLUDED.published,
            fixed = EXCLUDED.fixed,
            last_affected = EXCLUDED.last_affected,
            raw_data = EXCLUDED.raw_data,
            database_specific = EXCLUDED.database_specific;
    """

    try:
        conn = psycopg2.connect(**DB_PARAMS)
        cur = conn.cursor()
        execute_values(cur, query, processed_records)
        conn.commit()
        print(f"Успешно загружено {len(processed_records)} записей")
        for f in files_to_delete:
            os.remove(f)

    except Exception as e:
        print(f"Ошибка БД: {e}")
    finally:
        if "cur" in locals() and cur is not None:
            cur.close()
        if "conn" in locals() and conn is not None:
            conn.close()


if __name__ == "__main__":
    process_files()
