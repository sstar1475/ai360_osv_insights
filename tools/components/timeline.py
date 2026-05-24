"""
tools/components/timeline.py
Dash component wrapper for Timeline Analysis charts.
"""
from dash import dcc, html, callback, Input, Output, State

from tools.figures.timeline import build_quarterly_line, build_cumulative_area, build_seasonality_bar
from app.app import df_report

_CARD_STYLE = {
    'background': '#161b22',
    'border': '1px solid #30363d',
    'borderRadius': '12px',
    'padding': '24px',
    'marginBottom': '20px'
}

_DESC_STYLE = {
    'color': '#8b949e',
    'fontSize': '14px',
    'marginBottom': '20px',
    'lineHeight': '1.5'
}


def create_timeline_charts() -> html.Div:
    return html.Div([

        # ── Quarterly Line Chart ──────────────────────────────────────────────
        html.Div([
            html.H3(
                "Quarterly Vulnerability Trends",
                id='timeline-line-btn',
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
                    id='timeline-line-graph',
                    figure=build_quarterly_line(df_report),
                    config={'displayModeBar': False}
                )
            ], id='timeline-line-content', className='collapsible-content collapsed')
        ], style=_CARD_STYLE),

        # ── Cumulative Area Chart ─────────────────────────────────────────────
        html.Div([
            html.H3(
                "Fixed vs Unfixed Over Time",
                id='timeline-area-btn',
                className='collapsible-header',
                style={'marginTop': '0'}
            ),
            html.Div([
                html.P(
                    "Cumulative count of fixed vs still-unfixed vulnerabilities by year. "
                    "The gap between curves shows the growing security debt.",
                    style=_DESC_STYLE
                ),
                dcc.Graph(
                    id='timeline-area-graph',
                    figure=build_cumulative_area(df_report),
                    config={'displayModeBar': False}
                )
            ], id='timeline-area-content', className='collapsible-content collapsed')
        ], style=_CARD_STYLE),

        # ── Seasonality Bar Chart ─────────────────────────────────────────────
        html.Div([
            html.H3(
                "Seasonal Distribution by Month",
                id='timeline-season-btn',
                className='collapsible-header',
                style={'marginTop': '0'}
            ),
            html.Div([
                html.P(
                    "Distribution of vulnerability disclosures by month of year. "
                    "Blue bars are below average; orange bars are above average.",
                    style=_DESC_STYLE
                ),
                dcc.Graph(
                    id='timeline-season-graph',
                    figure=build_seasonality_bar(df_report),
                    config={'displayModeBar': False}
                )
            ], id='timeline-season-content', className='collapsible-content collapsed')
        ], style=_CARD_STYLE),
    ])


# ── Collapse callbacks ────────────────────────────────────────────────────────
@callback(
    Output('timeline-line-content', 'className'),
    Output('timeline-line-btn', 'className'),
    Input('timeline-line-btn', 'n_clicks'),
    State('timeline-line-content', 'className'),
    prevent_initial_call=True
)
def toggle_line(n, cls):
    return (('collapsible-content', 'collapsible-header active')
            if 'collapsed' in cls
            else ('collapsible-content collapsed', 'collapsible-header'))


@callback(
    Output('timeline-area-content', 'className'),
    Output('timeline-area-btn', 'className'),
    Input('timeline-area-btn', 'n_clicks'),
    State('timeline-area-content', 'className'),
    prevent_initial_call=True
)
def toggle_area(n, cls):
    return (('collapsible-content', 'collapsible-header active')
            if 'collapsed' in cls
            else ('collapsible-content collapsed', 'collapsible-header'))


@callback(
    Output('timeline-season-content', 'className'),
    Output('timeline-season-btn', 'className'),
    Input('timeline-season-btn', 'n_clicks'),
    State('timeline-season-content', 'className'),
    prevent_initial_call=True
)
def toggle_season(n, cls):
    return (('collapsible-content', 'collapsible-header active')
            if 'collapsed' in cls
            else ('collapsible-content collapsed', 'collapsible-header'))
