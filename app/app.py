import dash
from dash import html, dcc, Input, Output
from pathlib import Path
from db.OSVDataClient import OSVDataClient

external_stylesheets = [
    'https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;800&family=Open+Sans:wght@400;600&family=JetBrains+Mono:wght@400;600&display=swap'
]

print("[*] Connecting to database and initializing global OSV DataFrame...")

DB_CLIENT = OSVDataClient()
df_report = DB_CLIENT.get_detailed_report()

print(f"[+] Global DataFrame loaded successfully. Total rows cached: {len(df_report)}")


pages_path = Path(__file__).parent / 'pages'

app = dash.Dash(
    __name__,
    use_pages=True,
    pages_folder=str(pages_path),
    external_stylesheets=external_stylesheets,
    suppress_callback_exceptions=True
)
server = app.server

from tools.components.kata import create_kata_widget

app.layout = html.Div([
    dcc.Location(id='url', refresh=False),

    # Navigation Bar
    html.Div(
        id='nav-panel',
        style={
            "padding": "16px 40px",
            "display": "flex",
            "alignItems": "center",
            "justifyContent": "space-between",
            "marginBottom": "0"
        }
    ),

    # Page content
    html.Div(
        dash.page_container,
        style={
            'maxWidth': '1300px',
            'margin': '0 auto',
            'padding': '40px 24px'
        }
    ),

    # КАТА — кот-маскот (глобальный)
    create_kata_widget(),

], style={
    'fontFamily': "'Open Sans', sans-serif",
    'color': '#f0f6fc',
    'backgroundColor': '#0d1117',
    'minHeight': '100vh'
})


@app.callback(
    Output('nav-panel', 'children'),
    Input('url', 'pathname')
)
def update_navigation_menu(current_pathname):
    # Logo / Brand — без emoji-иконки
    logo = html.Div([
        html.Span("OSV", style={
            'fontFamily': "'Montserrat', sans-serif",
            'fontWeight': '800',
            'fontSize': '20px',
            'color': '#e67e22',
            'letterSpacing': '1px'
        }),
        html.Span(" Insights", style={
            'fontFamily': "'Montserrat', sans-serif",
            'fontWeight': '600',
            'fontSize': '20px',
            'color': '#f0f6fc',
            'letterSpacing': '0.5px'
        }),
        html.Span(" // OSV", style={
            'fontFamily': "'JetBrains Mono', monospace",
            'fontSize': '11px',
            'color': '#6e7681',
            'marginLeft': '10px',
            'letterSpacing': '1px'
        }),
    ], style={'display': 'flex', 'alignItems': 'center'})

    # Nav links
    menu_links = []
    for page in dash.page_registry.values():
        is_active = current_pathname == page["relative_path"]
        menu_links.append(
            dcc.Link(
                page['name'],
                href=page["relative_path"],
                className="nav-link active" if is_active else "nav-link",
                style={"margin": "0 14px"}
            )
        )

    nav_links = html.Div(menu_links, style={'display': 'flex', 'alignItems': 'center'})

    return [logo, nav_links]
