from dash import dcc, html, callback, Input, Output, State
from tools.figures.top_packages import build_top_packages_fig
from app.app import df_report

def create_top_packages_chart() -> html.Div:
    return html.Div([
        html.H3("Ecosystem Packages & Fix Rate Analysis", id='top-pkg-btn', className='collapsible-header', style={'color': '#e67e22', 'marginTop': '0', 'fontFamily': "'Montserrat', sans-serif"}),

        html.Div([
            html.Div([
                html.Div([
                    html.Label("Select Ecosystem:", style={'fontWeight': '600', 'marginRight': '10px', 'display': 'block', 'marginBottom': '5px', 'color': '#f0f6fc'}),
                    dcc.Dropdown(
                        id='ecosystem-dropdown',
                        options=[
                            {'label': 'PyPI', 'value': 'PyPI'},
                            {'label': 'npm', 'value': 'npm'},
                            {'label': 'Go', 'value': 'Go'},
                            {'label': 'Maven', 'value': 'Maven'}
                        ],
                        value='PyPI', clearable=False,
                        style={
                            'width': '200px',
                            'backgroundColor': '#1c2128',
                            'color': '#f0f6fc',
                            'border': '1px solid #30363d'
                        }
                    )
                ], style={'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '40px'}),

                html.Div([
                    html.Label("Show Top N Packages:", style={'fontWeight': '600', 'display': 'block', 'marginBottom': '5px', 'color': '#f0f6fc'}),
                    html.Div(
                        dcc.Slider(
                            id='top-packages-n-slider', min=5, max=30, step=5, value=15,
                            marks={i: str(i) for i in range(5, 31, 5)}, tooltip={"placement": "bottom", "always_visible": False}
                        ), style={'width': '300px'}
                    )
                ], style={'display': 'inline-block', 'verticalAlign': 'top'})
            ], style={'backgroundColor': '#21262d', 'padding': '20px', 'borderRadius': '12px', 'marginBottom': '20px', 'border': '1px solid #30363d'}),

            dcc.Graph(id='graph-top-packages', config={'displayModeBar': False})
        ], id='top-pkg-content', className='collapsible-content collapsed')
    ], style={'width': '100%', 'display': 'flex', 'flexDirection': 'column'})

@callback(
    Output('top-pkg-content', 'className'), Output('top-pkg-btn', 'className'),
    Input('top-pkg-btn', 'n_clicks'), State('top-pkg-content', 'className'), prevent_initial_call=True
)
def toggle_top_pkg_collapse(n_clicks, current_class):
    return ("collapsible-content", "collapsible-header active") if "collapsed" in current_class else ("collapsible-content collapsed", "collapsible-header")

@callback(
    Output('graph-top-packages', 'figure'),
    Input('ecosystem-dropdown', 'value'), Input('top-packages-n-slider', 'value')
)
def update_ecosystem_charts(selected_ecosystem, top_n):
    return build_top_packages_fig(df_report, selected_ecosystem, top_n=top_n)
