import sys
import pandas as pd

from pathlib import Path
parent_path = Path(__file__).resolve().parent
sys.path.insert(0, str(parent_path))
from tools.cwe_parse.cwe_parse import CWENode

def filter(df_report: pd.DataFrame, cwe_id: str)->pd.DataFrame:
    node = CWENode(cwe_id)
    _kids = node.get_descendants()
    kids = []
    for kid in _kids:
        kids.append(f"CWE-{kid}")

    return df_report[df_report["vulnerability_cwe_id"].isin(kids)]
def get_children(cwe_id: str):
    node = CWENode(cwe_id)
    return node.get_descendants("1")