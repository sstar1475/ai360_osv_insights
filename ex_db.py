import asyncio
from pandas import DataFrame
from db.OSVDataClient import OSVDataClient


async def main() -> None:
    """
    Initializes the asynchronous OSV data client, retrieves a limited dataset
    of vulnerabilities, and prints the resulting pandas DataFrame to the standard output.
    """
    client: OSVDataClient = OSVDataClient()
    vulns: DataFrame = await client.get_vulnerabilities(limit=100)
    print(vulns)


if __name__ == "__main__":
    asyncio.run(main())