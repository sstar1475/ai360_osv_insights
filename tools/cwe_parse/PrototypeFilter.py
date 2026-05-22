import asyncio
import sys
import pandas as pd
from cwe_parse import CWENode

def filter(df_report: pd.DataFrame, cwe_id: str)->pd.DataFrame:
    node = CWENode(cwe_id)
    _kids = node.get_descendants()
    kids = []
    for kid in _kids:
        kids.append(f"CWE-{kid}")

    return df_report[df_report["vulnerability_cwe_id"].isin(kids)]