import pandas as pd
import dash
import plotly.graph_objects as go
import sys
from pathlib import Path

parent_path = Path(__file__).resolve().parent
sys.path.insert(0, str(parent_path.parent))

from dash import dcc, html, Input, Output
from metrics import *
from cwe_parse.XMLConfigure import get_cwe_info
from cwe_parse.PrototypeFilter import filter as cwe_filter, get_children
from db.OSVDataClient import OSVDataClient

DB = OSVDataClient()
df = DB.get_detailed_report()

# Глобальный словарь метрик:
#   ключ       -> внутренний идентификатор (metric_1, metric_2, …)
#   func       -> функция, которая по DataFrame возвращает число
#   label      -> человекочитаемое название для подписей и интерфейса
ALL_METRICS = {
    'metric_1': {
        'func': calc_integral_severity,
        'label': 'интегральная метрика риска',
        'color': '#1f77b4'
    },
    'metric_2': {
        'func': calc_staleness_index,
        'label': 'индекс протухания зависимостей экосистемы (>2 лет без фикса)',
        'color': '#ff7f0e'
    },
    'metric_3': {
        'func': calc_avg_unfixed_life,
        'label': 'среднее время жизни (MTTR в днях) незакрытых дефектов безопасности',
        'color': '#2ca02c'
    },
    'metric_4': {
        'func': calc_high_severity_ratio,
        'label': 'доля критически опасных уязвимостей (>= HIGH / 7.0) в общей массе',
        'color': '#d62728'
    },
    'metric_5': {
        'func': calc_defect_density,
        'label': 'плотность дефектов безопасности',
        'color': '#9467bd'
    },
    'metric_6': {
        'func': calc_regression_rate,
        'label': 'индекс повторного появления уязвимостей',
        'color': '#8c564b'
    }
}

# Цвета для трасс разных метрик
COLORS = [ALL_METRICS[metric]['color'] for metric in ALL_METRICS.keys()]

# ---------- Вспомогательная функция для маппинга severity ----------
def map_severity(score):
    """Преобразует числовой CVSS score в категорию severity."""
    if pd.isna(score):
        return 'UNKNOWN'
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score >= 0.1:
        return 'LOW'
    else:
        return 'NONE'

# ---------- Новая функция: Stacked Bar Chart ----------
def create_stacked_bar_chart(df_report, group_by='ecosystem', normalized=False):
    """
    Строит многослойную столбчатую диаграмму распределения уязвимостей
    по уровням severity.

    Параметры:
    - df_report: DataFrame с данными OSV
    - group_by: 'ecosystem' (группировка по экосистемам) или
                'cwe_class' (группировка по CWE pillar)
    - normalized: если True, столбцы нормализованы до 100% внутри каждой группы
    """
    # Подготовка данных
    data = df_report.copy()

    # Определяем столбец severity: если есть 'severity', используем его,
    # иначе пытаемся получить из 'cvss_score'. Если нет ни того, ни другого – создаём 'UNKNOWN'
    if 'severity' not in data.columns:
        if 'cvss_score' in data.columns:
            data['severity'] = data['cvss_score'].apply(map_severity)
        else:
            data['severity'] = 'UNKNOWN'  # ← вместо выхода с сообщением

    # Определяем столбец группировки
    if group_by == 'ecosystem':
        group_col = 'ecosystem'  # или 'package_ecosystem', в зависимости от реальной схемы
        if group_col not in data.columns:
            # попробуем альтернативные названия
            for col in ['ecosystem', 'package_ecosystem', 'ecosystem_name']:
                if col in data.columns:
                    group_col = col
                    break
            else:
                # если экосистема совсем отсутствует, создаём заглушку
                data['ecosystem'] = 'Unknown'
                group_col = 'ecosystem'
    elif group_by == 'cwe_class':
        if 'cwe_id' not in data.columns:
            data['cwe_id'] = 'Unknown'
        # Извлекаем класс CWE (первые символы до тире, например 'CWE-1000' -> '1000')
        data['cwe_class'] = data['cwe_id'].astype(str).str.extract(r'CWE-(\d+)')
        # Для pillar можно оставить полный номер или взять только первую цифру,
        # здесь используем полный CWE ID как класс
        group_col = 'cwe_class'
    else:
        raise ValueError("group_by должен быть 'ecosystem' или 'cwe_class'")

    # Группируем и считаем количество
    grouped = data.groupby([group_col, 'severity']).size().reset_index(name='count')

    # Если нормализация, преобразуем в проценты внутри каждой группы
    if normalized:
        totals = grouped.groupby(group_col)['count'].transform('sum')
        grouped['count'] = (grouped['count'] / totals) * 100

    # Строим stacked bar
    severity_order = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN']
    severity_colors = {
        'NONE': '#b0bec5', 'LOW': '#66bb6a', 'MEDIUM': '#ffa726',
        'HIGH': '#ef5350', 'CRITICAL': '#ab47bc', 'UNKNOWN': '#78909c'
    }

    fig = go.Figure()
    for sev in severity_order:
        sub = grouped[grouped['severity'] == sev]
        if sub.empty:
            continue
        fig.add_trace(go.Bar(
            name=sev,
            x=sub[group_col],
            y=sub['count'],
            marker_color=severity_colors.get(sev, '#9e9e9e'),
            hovertemplate='%{x}<br>%{y:.1f}' + ('%' if normalized else '') + '<extra>%{name}</extra>'
        ))

    fig.update_layout(
        barmode='stack',
        title=f"Распределение уязвимостей по severity ({'нормировано' if normalized else 'абсолютные значения'})",
        xaxis_title="Группа",
        yaxis_title="Процент уязвимостей" if normalized else "Количество уязвимостей",
        template="plotly_white",
        height=500,
        legend_title="Severity"
    )

    return fig

def create_radial_chart(metric_columns: list, cwe_id: str = "1000") -> go.Figure:
    """
    Вычисляет все доступные метрики (из ALL_METRICS) для дочерних CWE
    и строит радарную диаграмму для выбранных metric_columns.
    Каждая выбранная метрика отображается отдельной линией.
    При наведении на края радара показывается детерминированный текст.
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

    # Получаем дочерние CWE
    children = get_children(cwe_id)

    # Считаем все метрики для каждого ребёнка
    result = {}
    for child in children:
        filtered_df = cwe_filter(df_report=df, cwe_id=child)
        result[child] = {
            key: info['func'](filtered_df) for key, info in ALL_METRICS.items()
        }

    # Фиксированный порядок CWE (по алфавиту/коду)
    cwe_list = sorted(result.keys(), key=lambda x: str(x))
    theta_vals = cwe_list + [cwe_list[0]]  # замыкаем многоугольник

    overall_max = 1.2
    fig = go.Figure()

    edge_texts = get_cwe_info()
    for idx, metric_key in enumerate(metric_columns):
        if metric_key not in ALL_METRICS:
            continue

        r_vals = [result[cwe][metric_key] for cwe in cwe_list]
        r_vals_closed = r_vals + [r_vals[0]]

        fig.add_trace(go.Scatterpolar(
            r=normalize(r_vals_closed),
            customdata=r_vals_closed,
            theta=theta_vals,
            mode='lines+markers',
            name=ALL_METRICS[metric_key]['label'],
            line=dict(color=COLORS[idx % len(COLORS)], width=2),
            marker=dict(size=6),
            fill='toself',
            hovertemplate="<b>%{theta}</b><br>" +
                          "Реальное значение: %{customdata}<br>" +
                          "Нормированное: %{r:.2f}<extra></extra>",
        ))

    # Невидимый слой с маркерами на краях осей для дополнительных подсказок
    edge_radius = overall_max * 1.05
    edge_r = [edge_radius] * len(cwe_list)
    edge_theta = cwe_list

    fig.add_trace(go.Scatterpolar(
        r=edge_r,
        theta=edge_theta,
        mode='markers',
        marker=dict(size=8, color='rgba(0,0,0,0)'),
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

# Dash-приложение с вкладками
app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1("Визуализации OSV данных", style={'textAlign': 'center'}),

    dcc.Tabs([
        dcc.Tab(label='Радарная диаграмма', children=[
            html.Div([
                html.Label("Выберите метрики для отображения:"),
                dcc.Checklist(
                    id='metric-checklist',
                    options=[{'label': info['label'], 'value': key} for key, info in ALL_METRICS.items()],
                    value=['metric_1'],
                    inline=False,
                    style={'margin-bottom': '20px'}
                ),
                dcc.Graph(id='radial-chart')
            ], style={'padding': '20px'})
        ]),
        dcc.Tab(label='Stacked Bar Chart', children=[
            html.Div([
                html.Label("Группировка:"),
                dcc.Dropdown(
                    id='group-by-dropdown',
                    options=[
                        {'label': 'Экосистема', 'value': 'ecosystem'},
                        {'label': 'CWE Класс (pillar)', 'value': 'cwe_class'}
                    ],
                    value='ecosystem',
                    clearable=False,
                    style={'width': '300px'}
                ),
                html.Label("Тип значений:", style={'margin-top': '15px'}),
                dcc.RadioItems(
                    id='value-mode-radio',
                    options=[
                        {'label': 'Абсолютные значения', 'value': 'absolute'},
                        {'label': 'Нормированные (100%)', 'value': 'normalized'}
                    ],
                    value='absolute',
                    style={'margin-bottom': '20px'}
                ),
                dcc.Graph(id='stacked-bar-chart')
            ], style={'padding': '20px'})
        ])
    ])
])

# Коллбэк для радарной диаграммы
@app.callback(
    Output('radial-chart', 'figure'),
    Input('metric-checklist', 'value')
)
def update_chart(selected_metrics):
    return create_radial_chart(metric_columns=selected_metrics, cwe_id="1000")

# Коллбэк для stacked bar chart
@app.callback(
    Output('stacked-bar-chart', 'figure'),
    Input('group-by-dropdown', 'value'),
    Input('value-mode-radio', 'value')
)
def update_stacked_chart(group_by, value_mode):
    normalized = (value_mode == 'normalized')
    return create_stacked_bar_chart(df, group_by=group_by, normalized=normalized)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)