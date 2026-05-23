import dash
from dash import html, dcc, Input, Output
from pathlib import Path
from db.OSVDataClient import OSVDataClient

external_stylesheets = [
    'https://fonts.googleapis.com/css2?family=Montserrat:wght@600;700&family=Open+Sans:wght@400;600&display=swap'
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
    external_stylesheets=external_stylesheets
)


nav_link_style = {
    "display": "inline-block",
    "margin": "0 20px",
    "fontWeight": "600",
    "fontSize": "16px",
    "color": "#2980b9",
    "textTransform": "uppercase",
    "letterSpacing": "1px"
}

app.layout = html.Div([
    dcc.Location(id='url', refresh=False),

    html.Div(
        id='nav-panel',
        style={
            "padding": "25px",
            "backgroundColor": "#ffffff",
            "borderBottom": "3px solid #e67e22",
            "textAlign": "center",
            "boxShadow": "0 2px 15px rgba(0,0,0,0.05)",
            "marginBottom": "50px"
        }
    ),

    html.Div(
        dash.page_container,
        style={
            'maxWidth': '1200px',
            'margin': '0 auto',
            'padding': '0 20px'
        }
    )
], style={
    'fontFamily': "'Open Sans', sans-serif",
    'color': '#333333',
    'backgroundColor': '#f8f9fa',
    'minHeight': '100vh'
})


@app.callback(
    Output('nav-panel', 'children'),
    Input('url', 'pathname')
)
def update_navigation_menu(current_pathname):
    menu_links = []
    for page in dash.page_registry.values():
        is_active = current_pathname == page["relative_path"]
        class_names = "nav-link active" if is_active else "nav-link"

        menu_links.append(
            dcc.Link(
                f"{page['name']}",
                href=page["relative_path"],
                style=nav_link_style,
                className=class_names
            )
        )
    return menu_links
