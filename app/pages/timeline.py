import dash
from dash import html

from tools.components.timeline import create_timeline_charts

dash.register_page(__name__, path='/timeline', name='Timeline Analysis')

_PAGE_STYLE = {
    'color': '#f0f6fc',
    'fontFamily': "'Open Sans', sans-serif"
}

layout = html.Div([
    html.H1(
        "Timeline Analysis",
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
        "Temporal patterns, quarterly trends, and seasonal distribution of vulnerabilities across ecosystems.",
        style={
            'textAlign': 'center',
            'color': '#8b949e',
            'fontSize': '15px',
            'marginBottom': '40px'
        }
    ),
    create_timeline_charts()
], style=_PAGE_STYLE)
