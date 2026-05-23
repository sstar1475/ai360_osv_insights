
import pandas as pd
import dash
import plotly.graph_objects as go
import sys
from pathlib import Path

parent_path = Path(__file__).resolve().parent
sys.path.insert(0, str(parent_path.parent))
from cwe_parse.XMLConfigure import get_cwe_info
from dash import dcc, html, Input, Output
from metrics import *
from cwe_parse.PrototypeFilter import filter as cwe_filter, get_children
from db.OSVDataClient import OSVDataClient

DB = OSVDataClient()
df = DB.get_detailed_report()

# Маппинг читаемых названий метрик на внутренние ключи колонок
METRIC_MAP = {
    'metric_1': 'доля уязвимостей без исправления более 730 дней',
    'metric_2': 'средний возраст (в днях) всех незакрытых уязвимостей',
    'metric_3': 'метрика риска по всем Affections'
}

# Индексы метрик в списке значений, вычисляемых в цикле
METRIC_INDEX = {'metric_1': 0, 'metric_2': 1, 'metric_3': 2}

# Цвета для трасс разных метрик
COLORS = ['#1f77b4', '#ff7f0e', '#2ca02c']

def create_radial_chart(metric_columns: list, cwe_id: str = "1000") -> go.Figure:
    """
    Вычисляет метрики для дочерних CWE и строит радарную диаграмму.
    Каждая выбранная метрика отображается отдельной линией.
    При наведении на угловые метки (края радара) выводится детерминированный текст.
    """
    if not metric_columns:
        fig = go.Figure()
        fig.add_annotation(
            text="Выберите хотя бы одну метрику",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False
        )
        fig.update_layout(height=400)
        return fig

    children = get_children(cwe_id)
    result = {}
    for child in children:
        filtered_df = cwe_filter(df_report=df, cwe_id=child)
        m1 = calc_staleness_index(filtered_df)
        m2 = calc_avg_unfixed_life(filtered_df)
        m3 = calc_integral_severity(filtered_df)
        result[child] = [m1, m2, m3]

    # Фиксированный порядок CWE
    cwe_list = sorted(result.keys(), key=lambda x: str(x))
    theta_vals = cwe_list + [cwe_list[0]]  # замыкаем многоугольник

    overall_max = 1.2
    fig = go.Figure()

    # Словарь с детерминированным текстом для каждой угловой метки (края)
    # Здесь в качестве примера — сам ID CWE, но может быть любая строка.
    edge_texts = get_cwe_info()

    # Основные линии метрик
    for idx, metric_key in enumerate(metric_columns):
        if metric_key not in METRIC_INDEX:
            continue
        data_idx = METRIC_INDEX[metric_key]
        r_vals = [result[cwe][data_idx] for cwe in cwe_list]
        r_vals += [r_vals[0]]  # замыкаем

        fig.add_trace(go.Scatterpolar(
            r=normalize(r_vals),
            customdata=r_vals,
            theta=theta_vals,
            mode='lines+markers',
            name=METRIC_MAP.get(metric_key, metric_key),
            line=dict(color=COLORS[idx % len(COLORS)], width=2),
            marker=dict(size=6),
            fill='toself',
            hovertemplate="<b>%{theta}</b><br>" +
                          "Реальное значение: %{customdata}<br>" +
                          "Нормированное: %{r:.2f}<extra></extra>",
        ))

    # Невидимый слой с точками на краях радара для всплывающих подсказок
    # Радиус берём чуть больше maximum, чтобы маркеры оказались за пределами области рисования
    # и не мешали восприятию, но hover всё равно сработает.
    edge_radius = overall_max * 1.05  # немного за границей видимой оси
    edge_r = [edge_radius] * len(cwe_list)
    edge_theta = cwe_list  # без замыкания, только уникальные углы

    fig.add_trace(go.Scatterpolar(
        r=edge_r,
        theta=edge_theta,
        mode='markers',
        marker=dict(size=8, color='rgba(0,0,0,0)'),  # полностью прозрачные маркеры
        hoverinfo='text',
        text=[edge_texts[cwe] for cwe in cwe_list],
        showlegend=False,
        name='Края осей'
    ))

    fig.update_layout(
        title=f"Радарная диаграмма: несколько метрик (родительский {cwe_id})",
        polar=dict(
            radialaxis=dict(visible=True, range=[0, overall_max * 1.1]),
            angularaxis=dict(direction="clockwise")
        ),
        template="plotly_white",
        height=650,
        showlegend=True
    )
    return fig

app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1("Радарная диаграмма метрик по CWE", style={'textAlign': 'center'}),
    html.Label("Выберите метрики для отображения:"),
    dcc.Checklist(
        id='metric-checklist',
        options=[{'label': label, 'value': key} for key, label in METRIC_MAP.items()],
        value=['metric_1'],  # по умолчанию выбрана первая
        inline=False,
        style={'margin-bottom': '20px'}
    ),
    dcc.Graph(id='radial-chart')
])

@app.callback(
    Output('radial-chart', 'figure'),
    Input('metric-checklist', 'value')
)
def update_chart(selected_metrics):
    return create_radial_chart(metric_columns=selected_metrics, cwe_id="1000")

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)