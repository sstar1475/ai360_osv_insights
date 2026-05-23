import plotly.graph_objects as go

from tools.config.metrics import ALL_METRICS
from tools.config.chart import RADAR_LAYOUT
from tools.metrics import normalize
from tools.cwe_parse.XMLConfigure import get_cwe_info
from tools.cwe_parse.PrototypeFilter import filter as cwe_filter, get_children


def build_radar_figure(df_source, metric_columns: list, cwe_id: str = "1000") -> go.Figure:
    """Генерирует Plotly Figure без HTML-оберток."""
    if not metric_columns:
        fig = go.Figure()
        fig.add_annotation(
            text="Please select at least one metric to visualize graph vectors",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(size=16, color="#e74c3c")
        )
        fig.update_layout(height=400, template="plotly_white")
        return fig

    children = get_children(cwe_id)
    result = {}
    for child in children:
        filtered_df = cwe_filter(df_report=df_source, cwe_id=child)
        result[child] = {key: info['func'](filtered_df) for key, info in ALL_METRICS.items()}

    cwe_list = sorted(result.keys(), key=lambda x: str(x))
    theta_vals = cwe_list + [cwe_list[0]]
    overall_max = 120
    fig = go.Figure()
    edge_texts = get_cwe_info()

    for metric_key in metric_columns:
        if metric_key not in ALL_METRICS: continue
        r_vals = [result[cwe][metric_key] for cwe in cwe_list]
        r_vals_closed = r_vals + [r_vals[0]]

        metric_color = ALL_METRICS[metric_key]['color']

        fig.add_trace(go.Scatterpolar(
            r=normalize(r_vals_closed),
            customdata=r_vals_closed,
            theta=theta_vals,
            mode='lines+markers',
            name=ALL_METRICS[metric_key]['label'],
            line=dict(color=metric_color, width=3),
            marker=dict(size=8),
            fill='toself',
            hovertemplate="<b>%{theta}</b><br>Real Value: %{customdata}<br>Normalized: %{r:.2f}% of maximum<extra></extra>",
        ))

    edge_radius = overall_max * 1.05
    fig.add_trace(go.Scatterpolar(
        r=[edge_radius] * len(cwe_list),
        theta=cwe_list,
        mode='markers',
        marker=dict(size=10, color='rgba(0,0,0,0)'),
        hoverinfo='text',
        text=[edge_texts.get(cwe, str(cwe)) for cwe in cwe_list],
        showlegend=False,
        name='Axis Edges'
    ))

    # Распаковываем статический словарь с дизайном
    fig.update_layout(**RADAR_LAYOUT)
    # Динамически добавляем range, который зависит от overall_max
    fig.layout.polar.radialaxis.range = [0, overall_max * 1.1]

    return fig
