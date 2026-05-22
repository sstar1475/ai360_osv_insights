import asyncio
import sys
from pathlib import Path
from cwe_parse import CWENode
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))
from db.OSVDataClient import OSVDataClient

df = OSVDataClient()

async def filter(df_report, cwe_id: str):
    node = CWENode(cwe_id)
    _kids = node.get_descendants()
    kids = []
    for kid in _kids:
        kids.append(f"CWE-{kid}")

    return df_report[df_report["vulnerability_cwe_id"].isin(kids)]
async def _db_():
    return await df.get_detailed_report()
df_rep = asyncio.run(_db_())
if __name__ == "__main__":
    ds = asyncio.run(filter(df_rep, "284"))
    print(ds)