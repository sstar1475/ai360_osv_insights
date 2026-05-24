from dash import dcc, html, callback, Input, Output, State
from tools.figures.risk_matrix import build_risk_matrix_fig
from app.app import df_report


def create_risk_matrix_chart() -> html.Div:
    return html.Div([
        html.H3("Ecosystem Risk Matrix", id='risk-matrix-btn', className='collapsible-header',
                style={'color': '#e67e22', 'marginTop': '0', 'fontFamily': "'Montserrat', sans-serif"}),

        html.Div([
            html.P(
                "Identifies dangerous packages. The X-axis shows average severity, the Y-axis shows the fix rate. Bubble size represents total vulnerabilities.",
                style={'color': '#7f8c8d', 'fontSize': '15px', 'marginBottom': '20px'}),

            html.Div([
                html.Div([
                    html.Label("Ecosystem:", style={'fontWeight': '600', 'marginRight': '10px', 'display': 'block',
                                                    'marginBottom': '5px'}),
                    dcc.Dropdown(
                        id='risk-matrix-ecosystem-dropdown',
                        options=[
                            {'label': 'All Ecosystems', 'value': 'All'},
                            {'label': 'PyPI', 'value': 'PyPI'},
                            {'label': 'npm', 'value': 'npm'},
                            {'label': 'Go', 'value': 'Go'},
                            {'label': 'Maven', 'value': 'Maven'}
                        ],
                        value='All', clearable=False, style={'width': '220px'}
                    )
                ], style={'display': 'inline-block', 'marginRight': '40px', 'verticalAlign': 'top'}),

                html.Div([
                    html.Label("Minimum Vulnerabilities per Package:",
                               style={'fontWeight': '600', 'marginRight': '15px', 'display': 'block',
                                      'marginBottom': '5px'}),
                    html.Div(
                        dcc.Slider(
                            id='risk-matrix-min-vulns-slider', min=1, max=50, step=1, value=10,
                            marks={1: '1', 10: '10', 20: '20', 30: '30', 50: '50+'},
                            tooltip={"placement": "bottom", "always_visible": False}
                        ), style={'width': '350px'}
                    )
                ], style={'display': 'inline-block', 'verticalAlign': 'top'})
            ], style={'backgroundColor': '#f8f9fa', 'padding': '20px', 'borderRadius': '12px', 'marginBottom': '20px',
                      'border': '1px solid #ecf0f1'}),

            dcc.Graph(id='graph-risk-matrix', config={'displayModeBar': False}, style={'height': '650px'})
        ], id='risk-matrix-content', className='collapsible-content collapsed')
    ], style={'width': '100%', 'display': 'flex', 'flexDirection': 'column'})


@callback(
    Output('risk-matrix-content', 'className'), Output('risk-matrix-btn', 'className'),
    Input('risk-matrix-btn', 'n_clicks'), State('risk-matrix-content', 'className'), prevent_initial_call=True
)
def toggle_risk_collapse(n_clicks, current_class):
    return ("collapsible-content", "collapsible-header active") if "collapsed" in current_class else (
        "collapsible-content collapsed", "collapsible-header")


@callback(
    Output('graph-risk-matrix', 'figure'),
    Input('risk-matrix-min-vulns-slider', 'value'), Input('risk-matrix-ecosystem-dropdown', 'value')
)
def update_risk_matrix(min_vulns, selected_ecosystem):
    return build_risk_matrix_fig(df_report, min_vulns, selected_ecosystem)
