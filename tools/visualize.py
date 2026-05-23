import pandas as pd
import dash
import plotly.graph_objects as go
import sys
import asyncio
from pathlib import Path
parent_path = Path(__file__).resolve().parent
sys.path.insert(0, str(parent_path.parent))

from dash import dcc, html, Input, Output
from metrics import *
from cwe_parse.PrototypeFilter import filter as cwe_filter, get_children
from db.OSVDataClient import OSVDataClient
# ── Функция построения радиальной диаграммы ─────────────────────────
def create_radial_chart(metric_column: str, cwe_id: str = "1000") -> go.Figure:
    """Загружает данные из БД, фильтрует по дочерним CWE, вычисляет метрики
    и строит радиальную столбчатую диаграмму (Barpolar).
    theta = идентификаторы дочерних CWE, r = значение выбранной метрики.
    """
    print(52)
    DB = OSVDataClient()
    df = DB.get_detailed_report()
    print(67)
    children = get_children(cwe_id)
    print(children)
    result = {}
    for child in children:
        filtered_df = cwe_filter(df_report=df, cwe_id=child)
        m1 = calc_staleness_index(filtered_df)
        m2 = calc_avg_unfixed_life(filtered_df)
        m3 = calc_integral_severity(filtered_df)
        result[child] = [m1, m2, m3]
        print(result[child])

    metrics_df = pd.DataFrame.from_dict(
        result, orient='index', columns=['metric_1', 'metric_2', 'metric_3']
    )
    metrics_df.index.name = 'cwe_id'
    metrics_df.reset_index(inplace=True)

    plot_data = metrics_df[['cwe_id', metric_column]].sort_values(metric_column, ascending=False)

    fig = go.Figure(
        go.Barpolar(
            r=plot_data[metric_column],
            theta=plot_data['cwe_id'],
            marker=dict(
                color=plot_data[metric_column],
                colorscale='Viridis',
                showscale=True,
                line=dict(color='white', width=1)
            ),
            hovertemplate=f'{metric_column}: %{{r}}<br>CWE: %{{theta}}<extra></extra>'
        )
    )

    fig.update_layout(
        title=f"Радиальная диаграмма: {metric_column} (родительский {cwe_id})",
        polar=dict(
            radialaxis=dict(visible=True, range=[0, plot_data[metric_column].max() * 1.1]),
            angularaxis=dict(direction="clockwise")
        ),
        template="plotly_white",
        height=650
    )
    return fig

# ── Dash приложение ─────────────────────────────────────────────────
app = dash.Dash(__name__) #перенести

# Доступные метрики (можно расширить)
AVAILABLE_METRICS = ['metric_1', 'metric_2', 'metric_3']

app.layout = html.Div([
    html.H1("Радиальная диаграмма метрик по CWE", style={'textAlign': 'center'}),
    html.Label("Выберите метрику:"),
    dcc.Dropdown(
        id='metric-dropdown',

        options=[{'label': m, 'value': m} for m in AVAILABLE_METRICS],
        value='metric_1',
        clearable=False,
        style={'width': '300px'}
    ),
    dcc.Graph(id='radial-chart')
])

@app.callback(
    Output('radial-chart', 'figure'),
    Input('metric-dropdown', 'value')
)

def update_chart(selected_metric):
    return create_radial_chart(metric_column=selected_metric, cwe_id="1000")

""" --------------- гпт сказал что код рабочий, но я ему не верю, пусть пока тут полежит, потом разберемся --------------- """
"""async def create_radial_chart(metric_column: str, cwe_id: str = "CWE-1000") -> go.Figure:
    import json, numpy as np, pandas as pd

    # ----- Тестовый DataFrame со всеми нужными колонками -----
    np.random.seed(42)
    n = 100
    severity_levels = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW']

    def make_unfixed_range():
        return json.dumps([{"events": [{"introduced": "1.0"}]}])

    df = pd.DataFrame({
        'vulnerability_cwe_id': np.random.choice(
            ['CWE-119', 'CWE-120', 'CWE-121', 'CWE-122', 'CWE-123'], n
        ),
        'vulnerability_published': pd.date_range('2024-01-01', periods=n, freq='D'),
        'vulnerability_severity_score': np.random.uniform(1.0, 10.0, n),
        'vulnerability_severity_text': np.random.choice(severity_levels, n),
        'affected_ranges': [make_unfixed_range() for _ in range(n)]
    })

    # ----- Ручной список дочерних CWE (без префикса) -----
    children = [119, 120, 121, 122, 123]   # они точно есть в df

    # ----- Расчёт метрик -----
    result = {}
    for child in children:
        filtered_df = cwe_filter(df_report=df, cwe_id=child)
        m1 = calc_staleness_index(filtered_df)
        m2 = calc_avg_unfixed_life(filtered_df)
        m3 = calc_integral_severity(filtered_df)
        result[child] = [m1, m2, m3]

    # ----- Построение графика (ваш код ниже) -----
    metrics_df = pd.DataFrame.from_dict(result, orient='index',
                                        columns=['metric_1', 'metric_2', 'metric_3'])
    metrics_df.index.name = 'cwe_id'
    metrics_df.reset_index(inplace=True)

    plot_data = metrics_df[['cwe_id', metric_column]].sort_values(metric_column, ascending=False)

    fig = go.Figure(go.Barpolar(
        r=plot_data[metric_column],
        theta=plot_data['cwe_id'],
        marker=dict(color=plot_data[metric_column], colorscale='Viridis', showscale=True,
                    line=dict(color='white', width=1)),
        hovertemplate=f'{metric_column}: %{{r}}<br>CWE: %{{theta}}<extra></extra>'
    ))

    fig.update_layout(
        title=f"Радиальная диаграмма: {metric_column} (родительский {cwe_id})",
        polar=dict(radialaxis=dict(visible=True,
                                   range=[0, plot_data[metric_column].max() * 1.1]),
                   angularaxis=dict(direction="clockwise")),
        template="plotly_white", height=650
    )
    return fig"""

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)