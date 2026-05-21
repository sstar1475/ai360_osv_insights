import plotly.express as px
import plotly.graph_objects as go
import pandas as pd


# def create_financial_bar_chart(df: pd.DataFrame, metric_name: str) -> go.Figure:
#     """
#     Генерирует объект Figure для Dash.
#     Принимает уже подготовленный DataFrame и название метрики.
#     """
#     color_map = {
#         'Продажи': '#1f77b4',
#         'Расходы': '#ff7f0e'
#     }
#
#     color = color_map.get(metric_name, '#7f7f7f')
#
#     fig = px.bar(
#         df,
#         x="Месяц",
#         y=metric_name,
#         title=f"Финансовые показатели: {metric_name}",
#         color_discrete_sequence=[color]
#     )
#
#     # Вся сложная стилизация графиков теперь живет в одном месте
#     fig.update_layout(
#         template="plotly_white",
#         xaxis_title="Период (2026 год)",
#         yaxis_title="Сумма (тыс. руб.)",
#         title_font=dict(size=18, family="Arial"),
#         margin=dict(l=40, r=40, t=60, b=40),
#         transition_duration=500
#     )
#
#     return fig
