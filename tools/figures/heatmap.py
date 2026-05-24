"""
tools/figures/heatmap.py
Heatmap: Ecosystem × CWE Pillar — mean CVSS severity score.
"""
import functools
import pandas as pd
import plotly.graph_objects as go

from tools.config.chart import HEATMAP_LAYOUT
from tools.cwe_parse.XMLConfigure import Parents, get_cwe_info

# The 10 root pillars of CWE-1000 Research Concepts view
_ROOT_PILLARS = {'284', '435', '664', '682', '691', '693', '697', '703', '707', '710'}


@functools.lru_cache(maxsize=10000)
def _get_root_pillar(cwe_str: str) -> str | None:
    """Walk up CWE parent chain until we hit one of the 10 root pillars."""
    current = str(cwe_str).replace('CWE-', '').strip()
    visited = set()
    while current not in visited:
        if current in _ROOT_PILLARS:
            return current
        visited.add(current)
        parents = Parents.get(current, set())
        if not parents:
            return None
        current = next(iter(parents))
    return None



def build_heatmap_figure(df: pd.DataFrame) -> go.Figure:
    """
    Creates a heatmap of mean CVSS score per (Ecosystem, CWE Pillar).
    Requires df with columns: package_ecosystem, vulnerability_cwe_id, vulnerability_severity_score.
    """
    required = {'package_ecosystem', 'vulnerability_cwe_id', 'vulnerability_severity_score'}
    if df.empty or not required.issubset(df.columns):
        return _empty_fig("Insufficient data for heatmap")

    df = df.copy()
    df['vulnerability_severity_score'] = pd.to_numeric(
        df['vulnerability_severity_score'], errors='coerce'
    )
    df = df.dropna(subset=['vulnerability_severity_score', 'vulnerability_cwe_id'])

    # Map each CWE to its root pillar
    df['cwe_str'] = df['vulnerability_cwe_id'].astype(str).str.replace('CWE-', '', regex=False).str.strip()
    df['cwe_pillar'] = df['cwe_str'].apply(_get_root_pillar)
    df = df.dropna(subset=['cwe_pillar'])

    pivot = (
        df.groupby(['package_ecosystem', 'cwe_pillar'])['vulnerability_severity_score']
        .mean()
        .round(2)
        .unstack(fill_value=None)
    )

    if pivot.empty:
        return _empty_fig("No CWE pillar data available")

    ecosystems = list(pivot.index)
    pillars = list(pivot.columns)
    z_values = pivot.values.tolist()

    # Text annotations
    text_vals = [
        [f"{v:.1f}" if v is not None and not pd.isna(v) else "" for v in row]
        for row in z_values
    ]

    fig = go.Figure(go.Heatmap(
        z=z_values,
        x=pillars,
        y=ecosystems,
        text=text_vals,
        texttemplate="%{text}",
        textfont=dict(size=12, color='#f0f6fc', family='JetBrains Mono'),
        colorscale=[
            [0.0,  '#1a3a2a'],
            [0.3,  '#2d6a4f'],
            [0.5,  '#eab308'],
            [0.7,  '#d97706'],
            [0.85, '#f85149'],
            [1.0,  '#7f1d1d'],
        ],
        colorbar=dict(
            title=dict(text="Avg CVSS", font=dict(color='#8b949e', size=12)),
            tickfont=dict(color='#8b949e', size=11),
            bgcolor='rgba(22,27,34,0.0)',
            bordercolor='#30363d',
            borderwidth=1,
            outlinecolor='#30363d',
        ),
        hovertemplate=(
            "<b>%{y}</b> × <b>%{x}</b><br>"
            "Avg CVSS: <b>%{z:.2f}</b><extra></extra>"
        ),
        xgap=2,
        ygap=2,
    ))

    layout = dict(**HEATMAP_LAYOUT)
    layout['title'] = dict(
        text='Avg CVSS Score: Ecosystem × CWE Pillar',
        font=dict(size=16, color='#f0f6fc', family='Montserrat'),
        x=0.01
    )
    fig.update_layout(**layout)
    fig.update_xaxes(tickangle=-35, tickfont=dict(size=10))
    return fig



def _empty_fig(message: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message, xref='paper', yref='paper', x=0.5, y=0.5,
        showarrow=False, font=dict(size=16, color='#8b949e')
    )
    fig.update_layout(paper_bgcolor='#161b22', plot_bgcolor='#161b22',
                      xaxis=dict(visible=False), yaxis=dict(visible=False))
    return fig
