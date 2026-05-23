import dash
from dash import html, dcc

dash.register_page(__name__, path='/', name='Home')

card_style = {
    'width': '42%',
    'padding': '30px',
    'margin': '2%',
    'backgroundColor': '#ffffff',
    'boxShadow': '0 6px 20px rgba(0, 0, 0, 0.06)',
    'borderRadius': '16px',
    'boxSizing': 'border-box',
    'textAlign': 'center',
    'cursor': 'pointer',
}

h2_style = {
    'color': '#e67e22',
    'marginTop': '0',
    'fontFamily': "'Montserrat', sans-serif",
    'fontSize': '26px',
    'marginBottom': '20px'
}

layout = html.Div([
    html.H1(
        "Welcome to OSV-insights!",
        style={
            'textAlign': 'center',
            'color': '#2c3e50',
            'fontFamily': "'Montserrat', sans-serif",
            'fontSize': '46px',
            'fontWeight': '700',
            'marginBottom': '60px'
        }
    ),

    html.Div([
        html.Div([
            html.Div([
                # Обертка имеет класс card-link, а заголовок - card-header
                dcc.Link([
                    html.H2("Common Statistics", style=h2_style, className="card-header"),
                    html.Img(src="/assets/bar_chart.png", style={'width': '85%', 'borderRadius': '8px'})
                ], href="/common", className="card-link")
            ], style=card_style),

            html.Div([
                dcc.Link([
                    html.H2("Package Analysis", style=h2_style, className="card-header"),
                    html.Img(src="/assets/sankey.png", style={'width': '85%', 'borderRadius': '8px'})
                ], href="/packages", className="card-link")
            ], style=card_style)
        ], style={'display': 'flex', 'justifyContent': 'center', 'width': '100%'}),

        html.Div([
            html.Div([
                dcc.Link([
                    html.H2("Vulnerability Analysis", style=h2_style, className="card-header"),
                    html.Img(src="/assets/radar.png", style={'width': '75%', 'maxWidth': '220px'})
                ], href="/affections", className="card-link")
            ], style=card_style),

            html.Div([
                dcc.Link([
                    html.H2("Terminology", style=h2_style, className="card-header"),
                    html.P(
                        "....a bit Boring text...",
                        style={
                            'fontSize': '22px',
                            'fontStyle': 'italic',
                            'color': '#7f8c8d',
                            'marginTop': '30px'
                        }
                    )
                ], href="/terminology", className="card-link")
            ], style=card_style)
        ], style={'display': 'flex', 'justifyContent': 'center', 'width': '100%'})
    ])
])
