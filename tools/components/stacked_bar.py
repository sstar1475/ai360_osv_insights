from dash import dcc, html, callback, Input, Output, State

from tools.figures.stacked_bar import build_stacked_bar_figure
from app.app import df_report


def create_stacked_bar_chart() -> html.Div:
    return html.Div([
        # Интерактивный заголовок
        html.H3(
            "Severity Distribution Analysis",
            id='stacked-collapse-btn',
            className='collapsible-header',  # УБРАЛИ 'active' — скрыто на старте
            style={'color': '#e67e22', 'marginTop': '0', 'fontFamily': "'Montserrat', sans-serif"}
        ),

        html.Div([
            html.P("Analyze vulnerability severity volumes across ecosystems or mitigation pillars.",
                   style={'color': '#7f8c8d', 'fontSize': '16px', 'marginBottom': '25px'}),

            # Панель управления (Фильтры)
            html.Div([
                html.Div([
                    html.Label("Group By:", style={'fontWeight': '600', 'color': '#f0f6fc', 'display': 'block',
                                                   'marginBottom': '8px'}),
                    dcc.Dropdown(
                        id='stacked-group-by-dropdown',
                        options=[
                            {'label': 'Package Ecosystem', 'value': 'ecosystem'},
                            {'label': 'CWE Class (Pillar)', 'value': 'cwe_class'}
                        ],
                        value='ecosystem',
                        clearable=False,
                        style={
                            'width': '100%',
                            'backgroundColor': '#1c2128',
                            'color': '#f0f6fc',
                            'border': '1px solid #30363d'
                        }
                    )
                ], style={'width': '45%', 'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '5%'}),

                html.Div([
                    html.Label("Calculation Mode:", style={'fontWeight': '600', 'color': '#f0f6fc', 'display': 'block',
                                                           'marginBottom': '8px'}),
                    dcc.RadioItems(
                        id='stacked-value-mode-radio',
                        options=[
                            {'label': ' Absolute Volumes', 'value': 'absolute'},
                            {'label': ' Normalized (100%)', 'value': 'normalized'}
                        ],
                        value='absolute',
                        labelStyle={'display': 'block', 'margin': '5px 0', 'color': '#f0f6fc', 'cursor': 'pointer'}
                    )
                ], style={'width': '45%', 'display': 'inline-block', 'verticalAlign': 'top'})

            ], style={'backgroundColor': '#21262d', 'padding': '25px', 'borderRadius': '12px',
                      'border': '1px solid #30363d', 'marginBottom': '20px'}),

            # Контейнер для графика
            dcc.Graph(
                id='stacked-bar-chart-graph',
                figure=build_stacked_bar_figure(df_report, group_by='ecosystem', normalized=False),
                config={'displayModeBar': False}
            )
        ], id='stacked-collapse-content', className='collapsible-content collapsed')  # ДОБАВИЛИ 'collapsed'

    ], style={'width': '100%', 'display': 'flex', 'flexDirection': 'column'})


# --- АНИМАЦИЯ СВОРАЧИВАНИЯ ---
@callback(
    Output('stacked-collapse-content', 'className'),
    Output('stacked-collapse-btn', 'className'),
    Input('stacked-collapse-btn', 'n_clicks'),
    State('stacked-collapse-content', 'className'),
    prevent_initial_call=True
)
def toggle_stacked_collapse(n_clicks, current_class):
    if "collapsed" in current_class:
        return "collapsible-content", "collapsible-header active"
    return "collapsible-content collapsed", "collapsible-header"


# --- ИНТЕРАКТИВНОСТЬ ГРАФИКА ---
@callback(
    Output('stacked-bar-chart-graph', 'figure'),
    Input('stacked-group-by-dropdown', 'value'),
    Input('stacked-value-mode-radio', 'value')
)
def update_stacked_interactivity(group_by, value_mode):
    normalized = (value_mode == 'normalized')
    return build_stacked_bar_figure(df_report, group_by=group_by, normalized=normalized)
