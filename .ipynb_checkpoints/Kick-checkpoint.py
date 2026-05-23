import asyncio
from db.OSVDataClient import OSVDataClient

async def main():
    db = OSVDataClient()

    # Получить уязвимости
    df_vuln = await db.get_vulnerabilities(limit=10)
    print("Vulnerabilities:")
    print(df_vuln)
    print("\n" + "=" * 50 + "\n")

    # Получить пакеты
    df_packages = await db.get_packages(limit=10)
    print("Packages:")
    print(df_packages)


if __name__ == "__main__":
    asyncio.run(main())