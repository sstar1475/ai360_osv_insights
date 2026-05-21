import json
import pandas as pd
import plotly.graph_objects as go

# def get_cwe_ecosystem_sankey(df: pd.DataFrame) -> dict | None:
#     """Возвращает JSON-представление графика для отправки по API"""
#     if df.empty:
#         return None
#
#     sources, targets, values, all_nodes = [], [], [], []
#
#     fig = go.Figure(data=[go.Sankey(
#         node=dict(pad=20, thickness=30, label=all_nodes),
#         link=dict(source=sources, target=targets, value=values)
#     )])
#
#     fig.update_layout(title_text="Поток уязвимостей", height=800)
#
#     return json.loads(fig.to_json())
