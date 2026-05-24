import plotly.graph_objects as go

from tools.config.metrics import ALL_METRICS
from tools.config.chart import RADAR_LAYOUT
from tools.metrics import normalize
from tools.cwe_parse.PrototypeFilter import filter as cwe_filter, get_children


def build_radar_figure(df_source, metric_columns: list, cwe_id: str = "1000") -> go.Figure:
    """Генерирует чистый объект go.Figure для переданного cwe_id."""
    if not metric_columns:
        fig = go.Figure()
        fig.add_annotation(text="Please select at least one metric", xref="paper", yref="paper", x=0.5, y=0.5,
                           showarrow=False)
        fig.update_layout(height=400, template="plotly_dark", paper_bgcolor="#161b22", plot_bgcolor="#161b22")
        return fig

    children = get_children(cwe_id)
    result = {}
    for child in children:
        filtered_df = cwe_filter(df_report=df_source, cwe_id=child)
        result[child] = {key: info['func'](filtered_df) for key, info in ALL_METRICS.items()}

    cwe_list = sorted(result.keys(), key=lambda x: str(x))

    # Если у узла нет детей (конечный лист дерева)
    if not cwe_list:
        fig = go.Figure()
        fig.add_annotation(text=f"No subcategories found for CWE-{cwe_id}", xref="paper", yref="paper", x=0.5, y=0.5,
                           showarrow=False, font=dict(size=16))
        fig.update_layout(height=400, template="plotly_dark", paper_bgcolor="#161b22", plot_bgcolor="#161b22")
        return fig

    theta_vals = cwe_list + [cwe_list[0]]
    overall_max = 120
    fig = go.Figure()

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
            hovertemplate="<b>%{theta}</b><br>Real Value: %{customdata}<br>Normalized: %{r:.2f}%<extra></extra>",
        ))

    fig.update_layout(**RADAR_LAYOUT)
    return fig
