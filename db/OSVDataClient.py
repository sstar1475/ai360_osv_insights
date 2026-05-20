import os
import warnings
from typing import Optional

import asyncpg
import pandas as pd
import paramiko
from dotenv import load_dotenv
from sshtunnel import SSHTunnelForwarder

if not hasattr(paramiko, "DSSKey"):
    setattr(paramiko, "DSSKey", None)

warnings.filterwarnings('ignore', category=UserWarning)

class OSVDataClient:

    ssh_host: str
    ssh_user: str
    ssh_password: str
    db_name: str
    db_user: str
    db_pass: str

    def __init__(self) -> None:
        load_dotenv()
        self.ssh_host = str(os.getenv("SSH_HOST"))
        self.ssh_user = str(os.getenv("SSH_USER"))
        self.ssh_password = str(os.getenv("SSH_PASSWORD"))
        self.db_name = str(os.getenv("DB_NAME"))
        self.db_user = str(os.getenv("DB_USER"))
        self.db_pass = str(os.getenv("DB_PASS"))

    async def query(self, sql_query: str) -> pd.DataFrame:
        """Выполняет любой SQL-запрос и возвращает чистый Pandas DataFrame"""
        with SSHTunnelForwarder(
            (self.ssh_host, 22),
            ssh_username=self.ssh_user,
            ssh_password=self.ssh_password,
            host_pkey_directories=[],
            allow_agent=False,
            remote_bind_address=("127.0.0.1", 5432),
        ) as tunnel:
            conn: asyncpg.Connection = await asyncpg.connect(
                host="127.0.0.1",
                port=tunnel.local_bind_port,
                database=self.db_name,
                user=self.db_user,
                password=self.db_pass,
            )
            try:
                records: list[asyncpg.Record] = await conn.fetch(sql_query)
                return pd.DataFrame([dict(r) for r in records])
            finally:
                await conn.close()

    async def get_vulnerabilities(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Универсальное получение всех полей из таблицы vulnerabilities"""
        sql: str = "SELECT * FROM vulnerabilities"
        if limit is not None:
            sql += f" LIMIT {limit}"
        return await self.query(sql)

    async def get_packages(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Универсальное получение всех полей из таблицы packages"""
        sql: str = "SELECT * FROM packages"
        if limit is not None:
            sql += f" LIMIT {limit}"
        return await self.query(sql)

    async def get_raw_affections(self, limit: Optional[int] = None) -> pd.DataFrame:
        """Универсальное получение всех полей из таблицы affections"""
        sql: str = "SELECT * FROM affections"
        if limit is not None:
            sql += f" LIMIT {limit}"
        return await self.query(sql)

    async def get_detailed_report(self, limit: Optional[int] = None) -> pd.DataFrame:
        """
        Объединяет все 3 таблицы, вытаскивая абсолютно все полезные данные без конфликтов имен
        """
        sql: str = '''
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
        '''
        if limit is not None:
            sql += f" LIMIT {limit}"
        return await self.query(sql)
