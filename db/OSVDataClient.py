import os
from pathlib import Path
import pandas as pd
import psycopg2
import warnings
from dotenv import load_dotenv
from sshtunnel import SSHTunnelForwarder

warnings.filterwarnings('ignore', category=UserWarning)

class OSVDataClient:

    def __init__(self):
        load_dotenv()
        self.ssh_host = os.getenv("SSH_HOST")
        self.ssh_user = os.getenv("SSH_USER")
        self.ssh_password = os.getenv("SSH_PASSWORD")

        self.db_name = os.getenv("DB_NAME")
        self.db_user = os.getenv("DB_USER")
        self.db_pass = os.getenv("DB_PASS")

    def query(self, sql_query: str) -> pd.DataFrame:
        """Выполняет любой SQL-запрос и возвращает чистый Pandas DataFrame"""
        with SSHTunnelForwarder(
            (self.ssh_host, 22),
            ssh_username=self.ssh_user,
            ssh_password=self.ssh_password,
            remote_bind_address=("127.0.0.1", 5432),
        ) as tunnel:

            conn = psycopg2.connect(
                host="127.0.0.1",
                port=tunnel.local_bind_port,
                database=self.db_name,
                user=self.db_user,
                password=self.db_pass,
            )

            try:
                df = pd.read_sql_query(sql_query, conn)
                return df
            finally:
                conn.close()

    def get_vulnerabilities(self, limit=None) -> pd.DataFrame:
        """Универсальное получение всех полей из таблицы vulnerabilities"""
        sql = "SELECT * FROM vulnerabilities"
        if limit is not None:
            sql += f" LIMIT {limit}"
        return self.query(sql)

    def get_packages(self, limit=None) -> pd.DataFrame:
        """Универсальное получение всех полей из таблицы packages"""
        sql = "SELECT * FROM packages"
        if limit is not None:
            sql += f" LIMIT {limit}"
        return self.query(sql)

    def get_raw_affections(self, limit=None) -> pd.DataFrame:
        """Универсальное получение всех полей из таблицы affections"""
        sql = "SELECT * FROM affections"
        if limit is not None:
            sql += f" LIMIT {limit}"
        return self.query(sql)

    def get_detailed_report(self, limit=None) -> pd.DataFrame:
        """
        Объединяет все 3 таблицы, вытаскивая абсолютно все полезные данные без конфликтов имен
        """
        sql = """
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
                a.ranges AS affected_ranges
            FROM affections a
            JOIN vulnerabilities v ON a.vuln_id = v.pk_id
            JOIN packages p ON a.pack_id = p.pk_id
        """
        if limit is not None:
            sql += f" LIMIT {limit}"
        return self.query(sql)
