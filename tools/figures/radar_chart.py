import textwrap
import plotly.graph_objects as go

from tools.config.metrics import ALL_METRICS
from tools.config.chart import RADAR_LAYOUT
from tools.metrics import normalize
from tools.cwe_parse.XMLConfigure import get_cwe_info
from tools.cwe_parse.PrototypeFilter import filter as cwe_filter, get_children


def build_radar_figure(df_source, metric_columns: list, cwe_id: str = "1000") -> go.Figure:
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

    # --- 1. ДИНАМИЧЕСКИЙ БЛОК ОПИСАНИЙ CWE (ПОЛНЫЙ ТЕКСТ) ---
    desc_lines = ["<span style='font-size:17px; font-weight:bold; color:#e67e22;'>CWE Prototypes:</span><br>"]
    for cwe in cwe_list:
        full_desc = edge_texts.get(cwe, "Unknown Category")

        # Разбиваем длинный текст на строки по ~50 символов
        # replace() добавляет отступы пробелами для второй и последующих строк, чтобы выровнять текст после "XXX — "
        wrapped_desc = textwrap.fill(full_desc, width=50).replace('\n',
                                                                  '<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;')
        desc_lines.append(f"<span style='font-weight:600;'>{cwe}</span> — {wrapped_desc}")

    cwe_desc_markdown = "<br>".join(desc_lines)

    # Применяем Layout
    fig.update_layout(**RADAR_LAYOUT)
    fig.layout.polar.radialaxis.range = [0, overall_max * 1.1]

    # Аннотация списка прототипов (Справа сверху)
    fig.add_annotation(
        x=0.58, y=1.0,
        xref="paper", yref="paper",
        xanchor="left", yanchor="top",
        text=cwe_desc_markdown,
        showarrow=False,
        align="left",
        font=dict(family="Open Sans, sans-serif", size=14, color="#2c3e50"),
        bgcolor="rgba(253, 253, 254, 0.95)",
        bordercolor="#e0e6ed",
        borderpad=12,
        borderwidth=1
    )

    # --- 2. БЛОК ТЕКУЩЕГО КОНТЕКСТА CWE (Справа снизу) ---
    current_cwe_title = f"CWE-{cwe_id}"
    # Берем описание родительского CWE. Если его нет (например, для корня "1000"), ставим дефолт
    current_cwe_desc = edge_texts.get(cwe_id, "Research Concepts / Root Node for Vulnerabilities")
    current_cwe_wrapped = textwrap.fill(current_cwe_desc, width=50).replace('\n', '<br>')

    current_context_text = (
        f"<span style='font-size:18px; font-weight:bold; color:#2c3e50;'>Current Node: {current_cwe_title}</span><br><br>"
        f"<span style='font-size:15px; color:#7f8c8d; font-style:italic;'>{current_cwe_wrapped}</span>"
    )

    # Аннотация контекста (Справа в самом низу, под легендой)
    fig.add_annotation(
        x=0.58, y=0.0,
        xref="paper", yref="paper",
        xanchor="left", yanchor="bottom",
        text=current_context_text,
        showarrow=False,
        align="left",
        font=dict(family="Open Sans, sans-serif", size=15, color="#2c3e50"),
        bgcolor="rgba(253, 253, 254, 0.95)",
        bordercolor="#e67e22",  # Выделим оранжевой рамкой для акцента
        borderpad=15,
        borderwidth=2
    )

    return fig
