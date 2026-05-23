# pages/affections.py
#!/usr/bin/env python3.13
import dash
from dash import html

dash.register_page(__name__, path='/affections', name='Vulnerabilities and Affections Analysis')

placeholder_card_style = {
    'width': '46%',
    'minHeight': '280px',
    'backgroundColor': '#ffffff',
    'boxShadow': '0 6px 20px rgba(0, 0, 0, 0.06)',
    'borderRadius': '16px',
    'padding': '20px',
    'boxSizing': 'border-box',
    'display': 'flex',
    'alignItems': 'center',
    'justifyContent': 'center',
    'color': '#95a5a6', 
    'fontFamily': "'Open Sans', sans-serif",
    'fontSize': '18px',
    'fontStyle': 'italic',
    'border': '2px dashed #ecf0f1'
}

grid_container_style = {
    'display': 'flex',
    'flexWrap': 'wrap',
    'justifyContent': 'center',
    'gap': '30px',
    'width': '100%',
    'padding': '10px'
}

layout = html.Div([
    html.H1(
        "Vulnerabilities and Affections Analysis", 
        style={
            'textAlign': 'center', 
            'color': '#2c3e50', 
            'fontFamily': "'Montserrat', sans-serif",
            'fontSize': '38px',
            'fontWeight': '700',
            'marginBottom': '50px'
        }
    ),

    # Сетка для графиков
    html.Div([
        html.Div("Радарная диаграмма метрик...", style=placeholder_card_style),
        html.Div("Connected Scatter Plot...", style=placeholder_card_style),
        html.Div("Распределение по Severity...", style=placeholder_card_style),
        html.Div("Patch Gap Analysis...", style=placeholder_card_style),
    ], style=grid_container_style)
])
