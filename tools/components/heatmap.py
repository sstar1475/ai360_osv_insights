"""
tools/components/heatmap.py
Dash component wrapper for the Ecosystem × CWE Pillar heatmap.
"""
from dash import dcc, html, callback, Input, Output, State

from tools.figures.heatmap import build_heatmap_figure
from app.app import df_report

_CARD_STYLE = {
    'background': '#161b22',
    'border': '1px solid #30363d',
    'borderRadius': '12px',
    'padding': '24px',
    'marginBottom': '20px'
}


def create_heatmap_chart() -> html.Div:
    return html.Div([
        html.H3(
            "Ecosystem × CWE Pillar Heatmap",
            id='heatmap-collapse-btn',
            className='collapsible-header',
            style={'marginTop': '0'}
        ),
        html.Div([
            html.P(
                "Average CVSS score grouped by ecosystem (rows) and CWE root pillar (columns). "
                "Darker red = higher severity; darker green = lower severity.",
                style={'color': '#8b949e', 'fontSize': '14px', 'marginBottom': '20px', 'lineHeight': '1.5'}
            ),
            dcc.Graph(
                id='heatmap-graph',
                figure=build_heatmap_figure(df_report),
                config={'displayModeBar': False}
            )
        ], id='heatmap-collapse-content', className='collapsible-content collapsed')
    ], style=_CARD_STYLE)


@callback(
    Output('heatmap-collapse-content', 'className'),
    Output('heatmap-collapse-btn', 'className'),
    Input('heatmap-collapse-btn', 'n_clicks'),
    State('heatmap-collapse-content', 'className'),
    prevent_initial_call=True
)
def toggle_heatmap(n, cls):
    return (('collapsible-content', 'collapsible-header active')
            if 'collapsed' in cls
            else ('collapsible-content collapsed', 'collapsible-header'))
