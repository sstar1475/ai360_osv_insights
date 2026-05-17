from datetime import datetime
from typing import List, Optional

from sqlalchemy import String, Integer, ForeignKey, Text, DateTime, UniqueConstraint, Table, Column
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.ext.associationproxy import association_proxy, AssociationProxy
from sqlalchemy.dialects.postgresql import JSONB


class Base(DeclarativeBase):
    pass


class Affection(Base):
    """
    Связующая таблица (Association Object) для Vulnerability и Package.
    Содержит дополнительные данные о связи (severity, ranges)
    """
    __tablename__ = "affections"

    vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.pk_id", ondelete="CASCADE"), primary_key=True)
    pack_id: Mapped[int] = mapped_column(ForeignKey("packages.pk_id", ondelete="CASCADE"), primary_key=True)

    severity: Mapped[Optional[str]] = mapped_column(String(64))
    ranges: Mapped[Optional[bytes]] = mapped_column(JSONB)

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="package_links")
    package: Mapped["Package"] = relationship(back_populates="vulnerability_links")

    def __repr__(self) -> str:
        return f"<Affection(vuln_id={self.vuln_id}, pack_id={self.pack_id})>"


class Vulnerability(Base):
    """
    Таблица уязвимостей
    """
    __tablename__ = "vulnerabilities"

    pk_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[Optional[str]] = mapped_column(String(64))
    summary: Mapped[Optional[str]] = mapped_column(Text)
    published: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    withdrawn: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    aliases: Mapped[List[Optional[str]]] = mapped_column(JSONB)
    upstream: Mapped[List[Optional[str]]] = mapped_column(JSONB)
    related: Mapped[List[Optional[str]]] = mapped_column(JSONB)

    severity: Mapped[Optional[str]] = mapped_column(String(64))
    cwe_id: Mapped[int] = mapped_column(Integer)
    severity_text: Mapped[Optional[str]] = mapped_column(String(16))

    package_links: Mapped[List["Affection"]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan"
    )

    packages: AssociationProxy[List["Package"]] = association_proxy(
        "package_links",
        "package"
    )


def __repr__(self) -> str:
    return f"<Vulnerability(id={self.pk_id}, cwe_id={self.cwe_id})>"


class Package(Base):
    """
    Таблица пакетов
    """
    __tablename__ = "packages"

    pk_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ecosystem: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(64))

    __table_args__ = (
        UniqueConstraint("ecosystem", "name", name="uix_package_ecosystem_name"),
    )

    vulnerability_links: Mapped[List["Affection"]] = relationship(
        back_populates="package",
        cascade="all, delete-orphan"
    )

    vulnerabilities: AssociationProxy[List["Vulnerability"]] = association_proxy(
        "vulnerability_links",
        "vulnerability"
    )

    def __repr__(self) -> str:
        return f"<Package(ecosystem={self.ecosystem}, name={self.name})>"
