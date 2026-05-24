import dash
from dash import html

from tools.components.radar_chart import create_radar_chart
from tools.components.stacked_bar import create_stacked_bar_chart
from tools.components.kpi_strip import create_affections_kpis
from app.app import df_report

dash.register_page(__name__, path='/affections', name='Vulnerability Analysis')

_CARD_STYLE = {
    'background': '#161b22',
    'border': '1px solid #30363d',
    'borderRadius': '16px',
    'padding': '28px',
    'marginBottom': '24px'
}

layout = html.Div([
    html.H1(
        "Vulnerability & Affection Analysis",
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
        "CWE drill-down radar, severity distributions, and ecosystem risk metrics.",
        style={
            'textAlign': 'center',
            'color': '#8b949e',
            'fontSize': '15px',
            'marginBottom': '32px'
        }
    ),

    # KPI strip (computed from real data)
    create_affections_kpis(df_report),

    # Radar Chart
    html.Div(create_radar_chart(), style=_CARD_STYLE),

    # Stacked Bar Chart
    html.Div(create_stacked_bar_chart(), style=_CARD_STYLE),
])
