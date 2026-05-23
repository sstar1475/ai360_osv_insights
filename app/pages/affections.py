import dash
from dash import html

from tools.components.radar_chart import create_radar_chart
from tools.components.stacked_bar import create_stacked_bar_chart

dash.register_page(__name__, path='/affections', name='Vulnerability Analysis')

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

real_card_style = {
    'width': '100%',
    'backgroundColor': '#ffffff',
    'boxShadow': '0 6px 20px rgba(0, 0, 0, 0.06)',
    'borderRadius': '16px',
    'padding': '30px',
    'boxSizing': 'border-box',
    'marginBottom': '30px'
}

layout = html.Div([
    html.H1(
        "Vulnerability & Affection Analysis", 
        style={
            'textAlign': 'center', 
            'color': '#2c3e50', 
            'fontFamily': "'Montserrat', sans-serif",
            'fontSize': '38px',
            'fontWeight': '700',
            'marginBottom': '50px'
        }
    ),

    html.Div([
        html.Div(create_radar_chart(), style=real_card_style),

        html.Div(create_stacked_bar_chart(), style=real_card_style),

        html.Div([
            html.Div("Connected Scatter Plot Analytics...", style=placeholder_card_style),
            html.Div("Patch Gap Timeline Chart...", style=placeholder_card_style),
        ], style=grid_container_style)
    ])
])
