import dash
from dash import html

from tools.components.risk_matrix import create_risk_matrix_chart
from tools.components.top_packages import create_top_packages_chart

dash.register_page(__name__, path='/packages', name='Package Risk Analytics')

real_card_style = {
    'width': '100%',
    'backgroundColor': '#ffffff',
    'boxShadow': '0 6px 20px rgba(0, 0, 0, 0.06)',
    'borderRadius': '16px',
    'padding': '25px',
    'boxSizing': 'border-box',
    'marginBottom': '25px'
}

layout = html.Div([
    html.H1(
        "Package Risk Analytics", 
        style={
            'textAlign': 'center', 
            'color': '#2c3e50', 
            'fontFamily': "'Montserrat', sans-serif",
            'fontSize': '38px',
            'fontWeight': '700',
            'marginBottom': '40px'
        }
    ),

    html.Div([
        html.Div(create_risk_matrix_chart(), style=real_card_style),
        html.Div(create_top_packages_chart(), style=real_card_style)
    ])
])
