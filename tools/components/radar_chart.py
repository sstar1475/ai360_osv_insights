import dash
from dash import dcc, html, callback, Input, Output, State, ALL

from tools.config.metrics import ALL_METRICS
from tools.figures.radar_chart import build_radar_figure
from tools.cwe_parse.XMLConfigure import get_cwe_info
from tools.cwe_parse.PrototypeFilter import get_children
from app.app import df_report


def create_radar_chart() -> html.Div:
    return html.Div([
        # Хранилище истории навигации
        dcc.Store(id='radar-cwe-history', data=['1000']),

        html.H3(
            "Risk Metrics Radar Analysis",
            id='radar-collapse-btn',
            className='collapsible-header',  # УБРАЛИ 'active' — теперь подчеркивание скрыто при старте
            style={'color': '#e67e22', 'marginTop': '0', 'fontFamily': "'Montserrat', sans-serif"}
        ),

        html.Div([
            html.P(
                "Comparative evaluation of sub-CWE categories across selected statistical parameters. Click on any sub-CWE item in the sidebar to drill down deeper into the inheritance tree.",
                style={'color': '#7f8c8d', 'fontSize': '16px', 'marginBottom': '25px'}),

            html.Div([
                html.Div([
                    html.Div([
                        html.Label("Select Metrics to Plot:",
                                   style={'fontWeight': '600', 'color': '#2c3e50', 'display': 'block',
                                          'marginBottom': '12px', 'fontSize': '16px'}),
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
                        config={'displayModeBar': False}
                    ),

                    html.Div(
                        [
                            html.Span("ℹ️ Normalization Note: ", style={'fontWeight': 'bold', 'color': '#34495e'}),
                            "Metric values are logarithmically scaled using the formula ",
                            html.Code("100 × log₂(1 + value / max_value)",
                                      style={
                                          'backgroundColor': '#ffffff',
                                          'padding': '2px 6px',
                                          'borderRadius': '4px',
                                          'color': '#e67e22',
                                          'fontSize': '12.5px',
                                          'border': '1px solid #e0e6ed'
                                      }),
                            ". This ensures that metrics with vastly different absolute scales remain visually comparable without extreme outliers flattening the graph."
                        ],
                        style={
                            'textAlign': 'center',
                            'color': '#7f8c8d',
                            'fontSize': '13px',
                            'marginTop': '10px',
                            'marginBottom': '20px',
                            'padding': '12px 20px',
                            'backgroundColor': '#f8f9fa',
                            'borderRadius': '8px',
                            'lineHeight': '1.6',
                            'fontFamily': "'Open Sans', sans-serif",
                            'width': '90%',
                            'marginLeft': 'auto',
                            'marginRight': 'auto',
                            'border': '1px solid #ecf0f1'
                        }
                    )
                ], style={'width': '62%', 'display': 'inline-block', 'verticalAlign': 'top'}),
                html.Div([
                    html.Button(
                        "← Back",
                        id='radar-back-btn',
                        className='radar-back-button',
                        n_clicks=0,
                        style={'display': 'none'}
                    ),

                    html.Div(id='radar-sidebar-context', className='cwe-sidebar-card',
                             style={'borderLeft': '4px solid #e67e22', 'backgroundColor': '#fff'}),

                    # Интерактивный список прототипов в сайдбаре
                    html.Div([
                        html.Div("CWE Prototypes (Click to toggle view):",
                                 id='prototypes-collapse-btn',
                                 className='collapsible-header',  # УБРАЛИ 'active'
                                 style={'fontSize': '16px', 'fontWeight': 'bold', 'color': '#e67e22',
                                        'marginBottom': '15px', 'fontFamily': "'Montserrat', sans-serif",
                                        'cursor': 'pointer'}),

                        # ДОБАВИЛИ 'collapsed' — список подкатегорий изначально свернут
                        html.Div(id='radar-sidebar-prototypes', className='collapsible-content collapsed')
                    ], className='cwe-sidebar-card')
                ], style={'width': '34%', 'display': 'inline-block', 'verticalAlign': 'top', 'marginLeft': '4%'})

            ], style={'width': '100%', 'display': 'block'})

        ], id='radar-collapse-content', className='collapsible-content collapsed')

    ], style={'width': '100%', 'display': 'flex', 'flexDirection': 'column'})


@callback(
    Output('radar-cwe-history', 'data'),
    Input({'type': 'cwe-link', 'index': ALL}, 'n_clicks'),
    Input('radar-back-btn', 'n_clicks'),
    State('radar-cwe-history', 'data'),
    prevent_initial_call=True
)
def handle_radar_navigation(links_clicked, back_clicked, current_history):
    trig_id = dash.ctx.triggered_id
    history = list(current_history) if current_history else ['1000']

    if trig_id == 'radar-back-btn':
        if len(history) > 1:
            history.pop()
        return history

    if isinstance(trig_id, dict) and trig_id.get('type') == 'cwe-link':
        if not any(links_clicked):
            return dash.no_update

        next_cwe = str(trig_id.get('index'))
        if next_cwe != history[-1]:
            history.append(next_cwe)
        return history

    return dash.no_update


@callback(
    Output('radar-chart-graph', 'figure'),
    Output('radar-sidebar-prototypes', 'children'),
    Output('radar-sidebar-context', 'children'),
    Output('radar-back-btn', 'style'),
    Output('radar-back-btn', 'children'),
    Input('radar-cwe-history', 'data'),
    Input('radar-metric-checklist', 'value')
)
def render_dynamic_radar_views(history, selected_metrics):
    history = history or ['1000']
    current_cwe = history[-1]

    fig = build_radar_figure(df_report, selected_metrics, cwe_id=current_cwe)
    edge_texts = get_cwe_info()
    children_ids = sorted(get_children(current_cwe), key=lambda x: str(x))

    prototype_elements = []
    for child in children_ids:
        child_desc = edge_texts.get(child, "Description unavailable.")
        prototype_elements.append(
            html.Div([
                html.Span(f"{child} ", style={'fontWeight': 'bold', 'color': '#2980b9', 'fontSize': '15px'}),
                html.Span(f"— {child_desc}")
            ], id={'type': 'cwe-link', 'index': child}, className='cwe-drilldown-item', n_clicks=0)
        )
    if not prototype_elements:
        prototype_elements = html.P("Leaf Node. No further subcategories found.",
                                    style={'fontStyle': 'italic', 'color': '#95a5a6', 'padding': '10px'})

    current_title = f"CWE-{current_cwe}"
    current_desc = edge_texts.get(current_cwe, "Research Concepts Hierarchy Base Node.")
    context_element = [
        html.Div(f"Current Level: {current_title}",
                 style={'fontSize': '18px', 'fontWeight': 'bold', 'color': '#2c3e50', 'marginBottom': '8px',
                        'fontFamily': "'Montserrat', sans-serif"}),
        html.P(current_desc, style={'fontSize': '14px', 'color': '#7f8c8d', 'fontStyle': 'italic', 'margin': '0',
                                    'lineHeight': '1.5'})
    ]

    if len(history) > 1:
        parent_cwe = history[-2]
        back_style = {'display': 'inline-flex'}
        back_text = f"← Back to CWE-{parent_cwe}"
    else:
        back_style = {'display': 'none'}
        back_text = ""

    return fig, prototype_elements, context_element, back_style, back_text


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
    Output('radar-sidebar-prototypes', 'className'),
    Output('prototypes-collapse-btn', 'className'),
    Input('prototypes-collapse-btn', 'n_clicks'),
    State('radar-sidebar-prototypes', 'className'),
    prevent_initial_call=True
)
def toggle_prototypes_collapse(n_clicks, current_class):
    if "collapsed" in current_class:
        return "collapsible-content", "collapsible-header active"
    return "collapsible-content collapsed", "collapsible-header"
