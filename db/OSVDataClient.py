import os
import atexit
import warnings
from typing import Optional

import pandas as pd
from dotenv import load_dotenv
from sshtunnel import SSHTunnelForwarder
from sqlalchemy import create_engine
import paramiko

if not hasattr(paramiko, "DSSKey"):
    paramiko.DSSKey = None

warnings.filterwarnings('ignore', category=UserWarning)

class OSVDataClient:
    def __init__(self) -> None:
        load_dotenv()
        self.ssh_host = str(os.getenv("SSH_HOST"))
        self.ssh_user = str(os.getenv("SSH_USER"))
        self.ssh_password = str(os.getenv("SSH_PASSWORD"))
        self.db_name = str(os.getenv("DB_NAME"))
        self.db_user = str(os.getenv("DB_USER"))
        self.db_pass = str(os.getenv("DB_PASS"))

        self.tunnel = SSHTunnelForwarder(
            (self.ssh_host, 22),
            ssh_username=self.ssh_user,
            ssh_password=self.ssh_password,
            host_pkey_directories=[],
            allow_agent=False,
            remote_bind_address=("127.0.0.1", 5432),
        )
        self.tunnel.start()

        db_url = f"postgresql+psycopg2://{self.db_user}:{self.db_pass}@127.0.0.1:{self.tunnel.local_bind_port}/{self.db_name}"
        self.engine = create_engine(
            db_url,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True
        )

        atexit.register(self.close)

    def close(self):
        """Корректное завершение работы"""
        self.engine.dispose()
        self.tunnel.stop()

    def query(self, sql_query: str) -> pd.DataFrame:
        """
        Выполняет запрос используя нативные и быстрые механизмы Pandas.
        Не создает новых подключений, берет готовое из пула.
        """
        return pd.read_sql(sql_query, con=self.engine)

    def get_vulnerabilities(self, limit: Optional[int] = None) -> pd.DataFrame:
        sql: str = "SELECT * FROM vulnerabilities"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        return self.query(sql)

    def get_packages(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Универсальное получение всех полей из таблицы packages"""
        sql: str = "SELECT * FROM packages"
        if limit is not None:
            sql += f" LIMIT {limit}"
        return self.query(sql)

    def get_raw_affections(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Универсальное получение всех полей из таблицы affections"""
        sql: str = "SELECT * FROM affections"
        if limit is not None:
            sql += f" LIMIT {limit}"
        return self.query(sql)

    def get_detailed_report(self, limit: Optional[int] = None) -> pd.DataFrame:
        """
        Объединяет все 3 таблицы, вытаскивая абсолютно все полезные данные без конфликтов имен.
        intro_date — минимальная дата 'introduced' из JSONB ranges (для метрик staleness/severity).
        """
        sql: str = r'''
            SELECT
                v.id AS vulnerability_id,
                v.summary AS vulnerability_summary,
                v.published AS vulnerability_published,
                v.withdrawn AS vulnerability_withdrawn,
                v.aliases AS vulnerability_aliases,
                v.upstream AS vulnerability_upstream,
                v.related AS vulnerability_related,
                v.severity AS vulnerability_severity_score,
                v.cwe_id AS vulnerability_cwe_id,
                v.severity_text AS vulnerability_severity_text,
                p.ecosystem AS package_ecosystem,
                p.name AS package_name,
                a.severity AS affected_severity,
                a.ranges AS affected_ranges,
                (
                    SELECT MIN(
                        CASE
                            WHEN (event->>'introduced') ~ '^\d{4}-\d{2}-\d{2}'
                            THEN (event->>'introduced')::timestamptz
                            ELSE NULL
                        END
                    )
                    FROM jsonb_array_elements(a.ranges) AS range_elem,
                         jsonb_array_elements(range_elem->'events') AS event
                    WHERE event ? 'introduced'
                      AND (event->>'introduced') IS NOT NULL
                      AND (event->>'introduced') != '0'
                ) AS intro_date,
                (
                    SELECT MAX((event->>'fixed')::text)
                    FROM jsonb_array_elements(a.ranges) AS range_elem,
                         jsonb_array_elements(range_elem->'events') AS event
                    WHERE event ? 'fixed'
                      AND (event->>'fixed') IS NOT NULL
                      AND (event->>'fixed') != '0'
                ) AS fixed_version
            FROM affections a
            JOIN vulnerabilities v ON a.vuln_id = v.pk_id
            JOIN packages p ON a.pack_id = p.pk_id
        '''
        if limit is not None:
            sql += f" LIMIT {limit}"
        return self.query(sql)

    def get_timeline_data(self) -> pd.DataFrame:
        """
        Агрегированные данные по кварталам для Timeline страницы.
        Возвращает количество новых уязвимостей по кварталам и экосистемам.
        """
        sql: str = '''
            SELECT
                DATE_TRUNC('quarter', v.published) AS quarter,
                p.ecosystem AS package_ecosystem,
                COUNT(DISTINCT v.id) AS vuln_count,
                COUNT(DISTINCT CASE
                    WHEN EXISTS (
                        SELECT 1
                        FROM jsonb_array_elements(a.ranges) AS r,
                             jsonb_array_elements(r->'events') AS e
                        WHERE e ? 'fixed'
                    ) THEN v.id
                END) AS fixed_count
            FROM affections a
            JOIN vulnerabilities v ON a.vuln_id = v.pk_id
            JOIN packages p ON a.pack_id = p.pk_id
            WHERE v.published IS NOT NULL
              AND v.published >= '2015-01-01'
            GROUP BY DATE_TRUNC('quarter', v.published), p.ecosystem
            ORDER BY quarter, package_ecosystem
        '''
        return self.query(sql)
