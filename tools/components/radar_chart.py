from dash import dcc, html, callback, Input, Output, State

from tools.config.metrics import ALL_METRICS
from tools.figures.radar_chart import build_radar_figure
from app.app import df_report


def create_radar_chart() -> html.Div:
    """Возвращает независимый HTML-блок с радаром и фильтрами."""
    return html.Div([
        html.H3(
            "Risk Metrics Radar Analysis",
            id='radar-collapse-btn',
            className='collapsible-header active',
            style={'color': '#e67e22', 'marginTop': '0', 'fontFamily': "'Montserrat', sans-serif"}
        ),

        html.Div([
            html.P("Comparative evaluation of sub-CWE categories across selected statistical parameters.",
                   style={'color': '#7f8c8d', 'fontSize': '16px', 'marginBottom': '25px'}),

            html.Div([
                html.Label("Select Metrics to Plot:",
                           style={'fontWeight': '600', 'color': '#2c3e50', 'display': 'block', 'marginBottom': '12px',
                                  'fontSize': '16px'}),
                dcc.Checklist(
                    id='radar-metric-checklist',
                    options=[{'label': info['label'], 'value': key} for key, info in ALL_METRICS.items()],
                    value=['metric_1', 'metric_3', 'metric_4'],
                    inline=False,
                    labelStyle={'display': 'block', 'margin': '8px 0', 'color': '#34495e', 'fontSize': '15px',
                                'cursor': 'pointer'}
                )
            ], style={'backgroundColor': '#f8f9fa', 'padding': '25px', 'borderRadius': '12px',
                      'border': '1px solid #ecf0f1', 'marginBottom': '20px'}),

            dcc.Graph(
                id='radar-chart-graph',
                # Инициализация первого рендера
                figure=build_radar_figure(df_report, ['metric_1'], "1000"),
                config={'displayModeBar': False}
            )
        ], id='radar-collapse-content', className='collapsible-content collapsed')

    ], style={'width': '100%', 'display': 'flex', 'flexDirection': 'column'})


@callback(
    Output('radar-collapse-content', 'className'),
    Output('radar-collapse-btn', 'className'),
    Input('radar-collapse-btn', 'n_clicks'),
    State('radar-collapse-content', 'className'),
    prevent_initial_call=True
)
def toggle_radar_collapse(n_clicks, current_class):
    if "collapsed" in current_class:
        return "collapsible-content", "collapsible-header active"
    return "collapsible-content collapsed", "collapsible-header"


@callback(
    Output('radar-chart-graph', 'figure'),
    Input('radar-metric-checklist', 'value')
)
def update_radar_interactivity(selected_metrics):
    return build_radar_figure(df_report, selected_metrics, cwe_id="1000")
