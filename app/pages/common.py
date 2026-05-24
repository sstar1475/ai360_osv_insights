import dash
from dash import html, dcc, callback, Input, Output, State
import pandas as pd

from tools.components.sankey import create_sankey_chart
from tools.figures.timeline import build_quarterly_line
from app.app import df_report

dash.register_page(__name__, path='/common', name='Common Statistics')

_PAGE_STYLE = {'color': '#f0f6fc', 'fontFamily': "'Open Sans', sans-serif"}

_CARD_STYLE = {
    'background': '#161b22',
    'border': '1px solid #30363d',
    'borderRadius': '16px',
    'padding': '28px',
    'marginBottom': '24px'
}

_DESC_STYLE = {
    'color': '#8b949e',
    'fontSize': '14px',
    'marginBottom': '20px',
    'lineHeight': '1.5'
}


layout = html.Div([
    html.H1(
        "Common Statistics",
        style={
            'textAlign': 'center',
            'fontFamily': "'Montserrat', sans-serif",
            'fontSize': '38px',
            'fontWeight': '700',
            'marginBottom': '8px',
            'color': '#f0f6fc'
        }
    ),
    html.P(
        "Vulnerability flows, CWE categories, and temporal trends.",
        style={
            'textAlign': 'center',
            'color': '#8b949e',
            'fontSize': '15px',
            'marginBottom': '40px'
        }
    ),

    # ── Quarterly Line Chart ──────────────────────────────────────────────
    html.Div([
        html.H3(
            "Quarterly Vulnerability Trends",
            id='common-line-btn',
            className='collapsible-header',
            style={'marginTop': '0'}
        ),
        html.Div([
            html.P(
                "Number of newly disclosed vulnerabilities per quarter, broken down by ecosystem. "
                "Observe growth spurts and ecosystem-level response patterns.",
                style=_DESC_STYLE
            ),
            dcc.Graph(
                id='common-line-graph',
                figure=build_quarterly_line(df_report),
                config={'displayModeBar': False}
            )
        ], id='common-line-content', className='collapsible-content collapsed')
    ], style=_CARD_STYLE),

    # Sankey (existing)
    html.Div(create_sankey_chart(), style=_CARD_STYLE),

], style=_PAGE_STYLE)


@callback(
    Output('common-line-content', 'className'),
    Output('common-line-btn', 'className'),
    Input('common-line-btn', 'n_clicks'),
    State('common-line-content', 'className'),
    prevent_initial_call=True
)
def toggle_line(n, cls):
    return (('collapsible-content', 'collapsible-header active')
            if 'collapsed' in cls
            else ('collapsible-content collapsed', 'collapsible-header'))

