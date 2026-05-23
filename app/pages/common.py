import dash
from dash import html

from tools.components.sankey import create_sankey_chart

dash.register_page(__name__, path='/common', name='Common Statistics')

# Стили для консистентности с остальным приложением
placeholder_card_style = {
    'width': '46%',
    'minHeight': '150px',
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
    'fontSize': '16px',
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
        "Common Statistics", 
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
        # Вставляем наш интерактивный и полностью переработанный блок Sankey
        html.Div(create_sankey_chart(), style=real_card_style),

        # Оставляем сетку плейсхолдеров для будущих графиков
        html.Div([
            html.Div("Vulnerability Distribution by Year...", style=placeholder_card_style),
            html.Div("Top Maintainers Affected...", style=placeholder_card_style),
            html.Div("Average Fix Time Trends...", style=placeholder_card_style),
            html.Div("Package Popularity vs Vulnerabilities...", style=placeholder_card_style),
        ], style=grid_container_style)
    ])
])
