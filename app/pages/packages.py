import dash
from dash import html

from tools.components.risk_matrix import create_risk_matrix_chart
from tools.components.top_packages import create_top_packages_chart
from tools.components.kpi_strip import create_packages_kpis
from app.app import df_report

dash.register_page(__name__, path='/packages', name='Package Risk Analytics')

_CARD_STYLE = {
    'background': '#161b22',
    'border': '1px solid #30363d',
    'borderRadius': '16px',
    'padding': '28px',
    'marginBottom': '24px'
}

layout = html.Div([
    html.H1(
        "Package Risk Analytics",
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
        "Risk matrix, top vulnerable packages, and package-level security debt metrics.",
        style={
            'textAlign': 'center',
            'color': '#8b949e',
            'fontSize': '15px',
            'marginBottom': '32px'
        }
    ),

    # KPI strip
    create_packages_kpis(df_report),

    # Risk Matrix
    html.Div(create_risk_matrix_chart(), style=_CARD_STYLE),

    # Top Packages
    html.Div(create_top_packages_chart(), style=_CARD_STYLE),
])
