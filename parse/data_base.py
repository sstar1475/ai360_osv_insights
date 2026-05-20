import json
import os
from pathlib import Path
import psycopg2
from dotenv import load_dotenv

BASE_DIR = Path(__file__).parent.parent

load_dotenv(BASE_DIR / ".env")

DB_PARAMS = {
    "host": os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
}

DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


def process_single_file(cur, json_file):
    """Парсит один комплексный OSV JSON и распределяет данные по 3 таблицам"""

    # Проверка MAL по имени файла
    if json_file.name.startswith("MAL-"):
        print(f"[MAL SKIP] Файл {json_file.name} пропущен (Malware).")
        return True

    with open(json_file, encoding="utf-8") as f:
        raw_json = json.load(f)

    osv_id = raw_json.get("id", "")

    # Проверка MAL по внутреннему ID
    if osv_id and osv_id.startswith("MAL-"):
        print(f"[MAL SKIP] Уязвимость {osv_id} пропущена (Malware).")
        return True

    # Сбор данных для таблицы vulnerabilities
    summary = raw_json.get("summary")
    published = raw_json.get("published")
    withdrawn = raw_json.get("withdrawn")
    aliases = json.dumps(raw_json.get("aliases", []))
    upstream = json.dumps(raw_json.get("upstream", {}))
    related = json.dumps(raw_json.get("related", []))

    # Поиск числовой оценки severity score внутри массива
    severity_score = None
    for sev in raw_json.get("severity", []):
        if "score" in sev:
            severity_score = sev["score"]
            break

    db_specific = raw_json.get("database_specific", {})
    cwe_id = db_specific.get("cwe_ids", [None])[0] if db_specific.get("cwe_ids") else None
    severity_text = db_specific.get("severity")

    # --- ЗАПИСЬ В VULNERABILITIES ---
    vuln_query = """
        INSERT INTO vulnerabilities (
            id, summary, published, withdrawn, aliases, upstream, related, severity, cwe_id, severity_text
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE SET
            summary = EXCLUDED.summary,
            published = EXCLUDED.published,
            withdrawn = EXCLUDED.withdrawn,
            aliases = EXCLUDED.aliases,
            upstream = EXCLUDED.upstream,
            related = EXCLUDED.related,
            severity = EXCLUDED.severity,
            cwe_id = EXCLUDED.cwe_id,
            severity_text = EXCLUDED.severity_text
        RETURNING pk_id;
    """
    cur.execute(vuln_query, (osv_id, summary, published, withdrawn, aliases, upstream, related, severity_score, cwe_id,
                             severity_text))
    vuln_pk_id = cur.fetchone()[0]

    # --- ЗАПИСЬ В PACKAGES И AFFECTIONS ---
    for affected_item in raw_json.get("affected", []):
        package_info = affected_item.get("package", {})
        ecosystem = package_info.get("ecosystem")
        name = package_info.get("name")

        if not ecosystem or not name:
            continue

        pack_query = """
            INSERT INTO packages (ecosystem, name)
            VALUES (%s, %s)
            ON CONFLICT (ecosystem, name) DO UPDATE SET name = EXCLUDED.name
            RETURNING pk_id;
        """
        cur.execute(pack_query, (ecosystem, name))
        pack_pk_id = cur.fetchone()[0]

        pkg_severity = affected_item.get("severity")
        ranges_json = json.dumps(affected_item.get("ranges", []))

        aff_query = """
            INSERT INTO affections (vuln_id, pack_id, severity, ranges)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (vuln_id, pack_id) DO UPDATE SET
                severity = EXCLUDED.severity,
                ranges = EXCLUDED.ranges;
        """
        cur.execute(aff_query, (vuln_pk_id, pack_pk_id, pkg_severity, ranges_json))

    return True


def main():
    conn = None
    files = list(DATA_DIR.glob("*.json"))

    if not files:
        print("Нет новых JSON файлов для обработки.")
        return

    try:
        conn = psycopg2.connect(**DB_PARAMS)
        cur = conn.cursor()

        success_count = 0

        for json_file in files:
            try:
                if process_single_file(cur, json_file):
                    conn.commit()
                    os.remove(json_file)
                    success_count += 1
            except Exception as file_error:
                if conn:
                    conn.rollback()
                print(f"Ошибка обработки файла {json_file.name}: {file_error}")

        if success_count > 0:
            print(f"Успешно обработано и удалено файлов: {success_count}")

    except Exception as db_error:
        print(f"Критическая ошибка подключения к БД: {db_error}")
    finally:
        if "cur" in locals() and cur is not None:
            cur.close()
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    main()
