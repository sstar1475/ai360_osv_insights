import os
import atexit
import warnings
from typing import Optional, Any, Dict

import pandas as pd
from dotenv import load_dotenv
from sshtunnel import SSHTunnelForwarder
from sqlalchemy import create_engine, text
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

    def query(self, sql_query: str, params: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
        """
        Выполняет запрос используя нативные и быстрые механизмы Pandas.
        Безопасно прокидывает параметры через SQLAlchemy text().
        """
        return pd.read_sql(text(sql_query), con=self.engine, params=params)

    def get_vulnerabilities(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Получение записей из таблицы vulnerabilities (по умолчанию — все)"""
        sql: str = "SELECT * FROM vulnerabilities"
        params = {}
        if limit is not None:
            sql += " LIMIT :limit_val"
            params["limit_val"] = int(limit)
        return self.query(sql, params=params)

    def get_packages(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Получение записей из таблицы packages (по умолчанию — все)"""
        sql: str = "SELECT * FROM packages"
        params = {}
        if limit is not None:
            sql += " LIMIT :limit_val"
            params["limit_val"] = int(limit)
        return self.query(sql, params=params)

    def get_raw_affections(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Получение записей из таблицы affections (по умолчанию — все)"""
        sql: str = "SELECT * FROM affections"
        params = {}
        if limit is not None:
            sql += " LIMIT :limit_val"
            params["limit_val"] = int(limit)
        return self.query(sql, params=params)

    def get_detailed_report(self, limit: Optional[int] = None) -> pd.DataFrame:
        """
        УНИВЕРСАЛЬНЫЙ МЕТОД: Собирает абсолютно все данные из базы в один датафрейм.
        Включает метаданные багов, пакеты, диапазоны и результаты обсчета таймлайнов.
        """
        sql: str = '''
            SELECT
                -- Данные из таблицы vulnerabilities
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
                
                -- Данные из таблицы packages
                p.ecosystem AS package_ecosystem,
                p.name AS package_name,
                
                -- Данные из таблицы affections
                a.severity AS affected_severity,
                a.ranges AS affected_ranges,
                
                -- Данные из таблицы affected_ranges (Обсчитанные таймлайны и коммиты)
                r.introduced_version,
                r.fixed_version,
                r.intro_date,
                r.commit_date, -- Наш новый филд для лагов
                r.fixed_date,
                r.days_vulnerable,
                r.status AS range_processing_status
            FROM affections a
            JOIN vulnerabilities v ON a.vuln_id = v.pk_id
            JOIN packages p ON a.pack_id = p.pk_id
            LEFT JOIN affected_ranges r ON r.vuln_id = a.vuln_id AND r.pack_id = a.pack_id
        '''
        params = {}
        if limit is not None:
            sql += " LIMIT :limit_val"
            params["limit_val"] = int(limit)
        return self.query(sql, params=params)
