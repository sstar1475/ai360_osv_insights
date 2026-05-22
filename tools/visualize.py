import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

import dash
from dash import dcc, html, Input, Output
import plotly.graph_objects as go
import pandas as pd
from tools.metrics import *
from tools.cwe_parse.PrototypeFilter import *
from db.OSVDataClient import OSVDataClient

# ── Функция построения радиальной диаграммы ─────────────────────────
async def create_radial_chart(metric_column: str, cwe_id: str = "CWE_1000") -> go.Figure:
    """
    Загружает данные из БД, фильтрует по дочерним CWE, вычисляет метрики
    и строит радиальную столбчатую диаграмму (Barpolar).
    theta = идентификаторы дочерних CWE, r = значение выбранной метрики.
    """
    # 1. Получить сырые данные
    db = OSVDataClient()
    df = db.get_detailed_report()

    # 2. Найти дочерние CWE для заданного cwe_id
    children = filter.get_children(data=df, cwe=cwe_id)

    # 3. Для каждого дочернего CWE вычислить метрики
    result = {}
    for child in children:
        filtered_df = filter.filter_for_children(data=df, cwe=child)
        m1 = calc_staleness_index(filtered_df)
        m2 = calc_avg_unfixed_life(filtered_df)
        m3 = calc_integral_severity(filtered_df)
        result[child] = [m1, m2, m3]
        print(result[child])

    # 4. Создать DataFrame с понятными названиями столбцов
    metrics_df = pd.DataFrame.from_dict(
        result, orient='index', columns=['metric_1', 'metric_2', 'metric_3']
    )
    metrics_df.index.name = 'cwe_id'
    metrics_df.reset_index(inplace=True)

    plot_data = metrics_df[['cwe_id', metric_column]].sort_values(metric_column, ascending=False)

    # Построить радиальную диаграмму
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
app = dash.Dash(__name__)

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
async def update_chart(selected_metric):
    # CWE_1000 задан жёстко, при необходимости можно добавить второй Dropdown
    return create_radial_chart(metric_column=selected_metric, cwe_id="CWE_1000")

if __name__ == '__main__':
    app.run(debug=True)