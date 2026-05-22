import os
import time
import requests
import psycopg2
from psycopg2.extras import DictCursor
from datetime import datetime, timezone
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
load_dotenv(BASE_DIR / ".env")

DB_PARAMS = {
    "host": os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
}

PACKAGE_CACHE = {}
NOW_DATE = datetime.now(timezone.utc)


def get_package_data_all(ecosystem, package):
    cache_key = f"{ecosystem}:{package}"
    if cache_key in PACKAGE_CACHE:
        return PACKAGE_CACHE[cache_key]

    versions_dict = {}
    try:
        api_package = "@strapi/strapi" if package == "strapi" else package
        if ecosystem == 'npm':
            url = f"https://registry.npmjs.org/{api_package}"
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                versions_dict = res.json().get("time", {})
                if 'created' in versions_dict:
                    versions_dict["0"] = versions_dict['created']
                    versions_dict["0.0.0"] = versions_dict['created']
        elif ecosystem == 'crates.io':
            url = f"https://crates.io/api/v1/crates/{api_package}"
            headers = {"User-Agent": "OsvEnricher/1.0"}
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200:
                sorted_v = sorted(res.json().get("versions", []), key=lambda x: x.get("created_at", ""))
                if sorted_v:
                    versions_dict["0"] = sorted_v[0].get("created_at")
                    versions_dict["0.0.0"] = sorted_v[0].get("created_at")
                for v in res.json().get("versions", []):
                    versions_dict[v.get("num")] = v.get("created_at")
    except Exception:
        pass

    PACKAGE_CACHE[cache_key] = versions_dict
    return versions_dict


def get_go_date(package, version):
    if not version or version == "0": return None
    if not version.startswith('v'): version = f"v{version}"
    url = f"https://proxy.golang.org/{package}/@v/{version}.info"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code == 200: return res.json().get("Time")
    except Exception:
        pass
    return None


def parse_date(date_str):
    if not date_str: return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        return None


def main():
    try:
        conn = psycopg2.connect(**DB_PARAMS)
        cur = conn.cursor(cursor_factory=DictCursor)
    except Exception as db_error:
        print(f"Критическая ошибка подключения к БД: {db_error}")
        return

    # Забираем необсчитанные интервалы версий
    query = """
        SELECT r.pk_id, r.introduced_version, r.fixed_version, p.name, p.ecosystem
        FROM public.affected_ranges r
        JOIN public.packages p ON r.pack_id = p.pk_id
        WHERE r.status = 'PENDING'
        LIMIT 500;
    """

    cur.execute(query)
    rows = cur.fetchall()

    if not rows:
        print("Все имеющиеся интервалы версий уже обогащены датами. Новых строк нет.")
        cur.close()
        conn.close()
        return

    print(f"Найдено {len(rows)} строк для вычисления дат...")
    success_count = 0

    for row in rows:
        pk_id = row['pk_id']
        eco = row['ecosystem']
        pkg = row['name']
        intro_v = row['introduced_version']
        fixed_v = row['fixed_version']

        intro_raw_date = None
        fixed_raw_date = None

        # Получаем сырые даты из API
        if eco in ['npm', 'crates.io']:
            pkg_dates = get_package_data_all(eco, pkg)
            if pkg_dates:
                intro_raw_date = pkg_dates.get(intro_v)
                if fixed_v:
                    fixed_raw_date = pkg_dates.get(fixed_v)
        elif eco == 'Go' and pkg != 'stdlib':
            if intro_v != '0':
                intro_raw_date = get_go_date(pkg, intro_v)
            if fixed_v:
                fixed_raw_date = get_go_date(pkg, fixed_v)
            time.sleep(0.01) 

        intro_date = parse_date(intro_raw_date)
        fixed_date = parse_date(fixed_raw_date)

        # Математика расчета жизненного цикла
        days_vulnerable = None
        if intro_date:
            if fixed_date:
                days_vulnerable = round((fixed_date - intro_date).total_seconds() / 86400, 1)
            elif not fixed_v:  # Фикса нет совсем
                days_vulnerable = round((NOW_DATE - intro_date).total_seconds() / 86400, 1)

        # Пишем расчеты обратно в запись таблицы affected_ranges
        update_query = """
            UPDATE public.affected_ranges
            SET intro_date = %s, fixed_date = %s, days_vulnerable = %s, status = 'PROCESSED'
            WHERE pk_id = %s;
        """
        try:
            cur.execute(update_query, (intro_date, fixed_date, days_vulnerable, pk_id))
            success_count += 1
        except Exception as write_error:
            print(f"Ошибка сохранения строки ID {pk_id}: {write_error}")

    conn.commit()
    print(f"Успешно обогащено и сохранено записей в этой пачке: {success_count}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
