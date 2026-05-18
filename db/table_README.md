# 📚 OSV Database: Документация по ORM моделям

Этот репозиторий содержит асинхронные SQLAlchemy 2.0 модели для хранения, связи и анализа уязвимостей Open Source (база OSV). Код оптимизирован для работы с PostgreSQL и написан под Python 3.13.7.

## 1. Архитектура и логика хранения данных

Ключевая особенность схемы — разделение идентификаторов на суррогатные и естественные. Это сделано для максимальной производительности СУБД при построении сложных графов:

* **`pk_id` (Суррогатный ключ):** Быстрое целочисленное поле (`Integer`, `autoincrement`). Используется **исключительно под капотом** базы данных для мгновенных `JOIN`'ов и связей (Foreign Keys) между таблицами.
* **`id` (Естественный ключ):** Текстовое поле из исходного JSON (например, `"CVE-2024-1234"`). Имеет ограничение `unique=True`. Используется для поиска уязвимостей по их реальному имени.

### Основные таблицы
* **`Vulnerability` (Уязвимости):** Хранит метаданные инцидента. Включает JSONB-поля (`aliases`, `upstream`, `related`) для гибкого хранения сырых массивов из OSV.
* **`Package` (Пакеты):** Справочник затронутых библиотек. Идентифицируется уникальной парой `ecosystem` + `name` (например, "npm" + "react").
* **`Affection` (Связующая таблица):** Реализует паттерн *Association Object* для связи «Многие-ко-многим». Хранит данные, специфичные для конкретной связи пакета и уязвимости (какие конкретно `ranges` версий затронуты).

### Графовые связи
Таблицы `alias_edges`, `upstream_edges` и `related_edges` позволяют строить ориентированные графы. Модель `Vulnerability` автоматически собирает связанных соседей через свойства (например, `vuln.equivalent_aliases` вернет плоский список всех клонов уязвимости, склеив входящие и исходящие ребра).

---

## 2. Примеры использования (Справочник разработчика)

### Запись данных (Парсинг JSON)

При парсинге сырых JSON-дампов необходимо сначала проверить существование пакета, чтобы не нарушить `UniqueConstraint`, а затем связать его с уязвимостью.

```python
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from tables import Vulnerability, Package, Affection

async def save_parsed_osv(session: AsyncSession, json_data: dict) -> None:
    # 1. Ищем пакет или создаем новый (Upsert-логика)
    stmt = select(Package).where(
        Package.ecosystem == json_data["ecosystem"],
        Package.name == json_data["package_name"]
    )
    package = await session.scalar(stmt)
    
    if not package:
        package = Package(
            ecosystem=json_data["ecosystem"],
            name=json_data["package_name"]
        )
        session.add(package)
        await session.flush() # Получаем package.pk_id

    # 2. Создаем запись об уязвимости
    vuln = Vulnerability(
        id=json_data["id"], # Реальный строковый ID (например, GHSA-...)
        summary=json_data.get("summary"),
        cwe_id=json_data.get("cwe_id", 0),
        aliases=json_data.get("aliases") # Сохраняется напрямую в JSONB
    )
    session.add(vuln)
    await session.flush() # Получаем vuln.pk_id

    # 3. Связываем их через Affection, добавляя уязвимые диапазоны
    affection = Affection(
        vuln_id=vuln.pk_id,
        pack_id=package.pk_id,
        ranges=json_data.get("ranges")
    )
    session.add(affection)
    
    await session.commit()
```

### Поиск и фильтрация (Querying)


```python
from sqlalchemy import select, and_, or_
from tables import Vulnerability, Package, Affection

async def search_examples(session: AsyncSession) -> None:
    # --- 1. Точный поиск по строковому ID ---
    stmt = select(Vulnerability).where(Vulnerability.id == "CVE-2024-0001")
    vuln = await session.scalar(stmt)

    # --- 2. Использование ILIKE (регистронезависимый поиск по тексту) ---
    stmt = select(Vulnerability).where(
        Vulnerability.summary.ilike("%buffer overflow%")
    )
    overflow_vulns = (await session.scalars(stmt)).all()

    # --- 3. Сложные фильтры (AND / OR) ---
    stmt = select(Vulnerability).where(
        and_(
            Vulnerability.cwe_id.in_([79, 89]), # SQLi или XSS
            Vulnerability.severity_text == "HIGH"
        )
    )
    high_vulns = (await session.scalars(stmt)).all()

    # --- 4. JOIN: Найти все уязвимости для конкретного пакета ---
    stmt = (
        select(Vulnerability)
        .join(Affection, Vulnerability.pk_id == Affection.vuln_id)
        .join(Package, Package.pk_id == Affection.pack_id)
        .where(
            Package.name == "requests",
            Package.ecosystem == "PyPI"
        )
    )
    requests_vulns = (await session.scalars(stmt)).all()

    # --- 5. Работа с графами (Элиасы) ---
    stmt = select(Vulnerability).where(Vulnerability.id == "CVE-2023-100")
    vuln = await session.scalar(stmt)
    if vuln:
        # Автоматически достает всех соседей по графу (туда и обратно)
        for clone in vuln.equivalent_aliases:
            print(f"Связанный алиас: {clone.id} (PK: {clone.pk_id})")

```
