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
            className='collapsible-header',
            style={'color': '#e67e22', 'marginTop': '0', 'fontFamily': "'Montserrat', sans-serif"}
        ),

        html.Div([
            html.P(
                "Comparative evaluation of sub-CWE categories across selected metrics. Click any CWE in the sidebar to drill down.",
                style={'color': '#8b949e', 'fontSize': '14px', 'marginBottom': '20px'}),

            html.Div([
                # ── Left: metrics selector + chart + formula ──────────────────
                html.Div([
                    # Metrics checklist
                    html.Div([
                        html.Label("Select Metrics to Plot:",
                                   style={'fontWeight': '600', 'color': '#f0f6fc', 'display': 'block',
                                          'marginBottom': '10px', 'fontSize': '14px'}),
                        dcc.Checklist(
                            id='radar-metric-checklist',
                            options=[{'label': info['label'], 'value': key} for key, info in ALL_METRICS.items()],
                            value=['metric_1', 'metric_3', 'metric_4'],
                            inline=False,
                            labelStyle={'display': 'block', 'margin': '6px 0', 'color': '#c9d1d9',
                                        'fontSize': '13px', 'cursor': 'pointer'}
                        )
                    ], style={
                        'backgroundColor': '#21262d',
                        'padding': '16px 20px',
                        'borderRadius': '10px',
                        'border': '1px solid #30363d',
                        'marginBottom': '16px'
                    }),

                    dcc.Graph(id='radar-chart-graph', config={'displayModeBar': False}),

                    # Normalization note — полностью тёмный
                    html.Div([
                        html.Span("Normalization: ", style={
                            'fontWeight': '700', 'color': '#e67e22', 'fontSize': '12px'
                        }),
                        html.Code("100 × log₂(1 + value / max_value)", style={
                            'backgroundColor': '#0d1117',
                            'padding': '2px 8px',
                            'borderRadius': '4px',
                            'color': '#58a6ff',
                            'fontSize': '12px',
                            'border': '1px solid #30363d',
                            'fontFamily': "'JetBrains Mono', monospace"
                        }),
                        html.Span(
                            " — log-scale keeps all metrics comparable without outlier flattening.",
                            style={'color': '#6e7681', 'fontSize': '12px'}
                        )
                    ], style={
                        'marginTop': '8px',
                        'padding': '10px 16px',
                        'backgroundColor': '#161b22',
                        'borderRadius': '8px',
                        'border': '1px solid #21262d',
                        'lineHeight': '1.6'
                    })
                ], style={'width': '62%', 'display': 'inline-block', 'verticalAlign': 'top'}),

                # ── Right: CWE sidebar ────────────────────────────────────────
                html.Div([
                    # Back button
                    html.Button(
                        "← Back",
                        id='radar-back-btn',
                        className='radar-back-button',
                        n_clicks=0,
                        style={'display': 'none'}
                    ),

                    # Current CWE context — полностью тёмный
                    html.Div(id='radar-sidebar-context', style={
                        'backgroundColor': '#21262d',
                        'border': '1px solid #30363d',
                        'borderLeft': '4px solid #e67e22',
                        'borderRadius': '8px',
                        'padding': '14px 16px',
                        'marginBottom': '12px'
                    }),

                    # CWE Prototypes — компактный аккордеон
                    html.Div([
                        html.Div(
                            id='prototypes-collapse-btn',
                            className='collapsible-header',
                            style={'cursor': 'pointer', 'padding': '8px 0', 'marginBottom': '0'},
                            children=[
                                html.Span("CWE Prototypes", style={
                                    'fontWeight': '700',
                                    'fontSize': '13px',
                                    'color': '#e67e22',
                                    'fontFamily': "'Montserrat', sans-serif"
                                }),
                                html.Span(" (click to expand)", style={
                                    'fontSize': '11px',
                                    'color': '#6e7681'
                                }),
                            ]
                        ),
                        # Список — изначально скрыт через display:none
                        html.Div(
                            id='radar-sidebar-prototypes',
                            style={
                                'display': 'none',
                                'maxHeight': '340px',
                                'overflowY': 'auto',
                                'overflowX': 'hidden',
                                'paddingRight': '4px',
                                'marginTop': '8px'
                            }
                        )
                    ], style={
                        'backgroundColor': '#21262d',
                        'border': '1px solid #30363d',
                        'borderRadius': '8px',
                        'padding': '10px 14px'
                    })
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
        # Compact single-line item
        prototype_elements.append(
            html.Div([
                html.Span(f"CWE-{child}", style={
                    'fontWeight': '700',
                    'color': '#58a6ff',
                    'fontSize': '12px',
                    'fontFamily': "'JetBrains Mono', monospace",
                    'marginRight': '6px',
                    'whiteSpace': 'nowrap'
                }),
                html.Span(child_desc, style={
                    'color': '#8b949e',
                    'fontSize': '12px',
                    'overflow': 'hidden',
                    'textOverflow': 'ellipsis',
                    'whiteSpace': 'nowrap',
                    'flex': '1'
                })
            ],
                id={'type': 'cwe-link', 'index': child},
                className='cwe-drilldown-item',
                n_clicks=0,
                style={
                    'display': 'flex',
                    'alignItems': 'center',
                    'gap': '4px',
                    'padding': '5px 8px',
                    'borderRadius': '6px',
                    'cursor': 'pointer',
                    'marginBottom': '2px'
                }
            )
        )

    if not prototype_elements:
        prototype_elements = html.P(
            "Leaf Node — no further subcategories.",
            style={'fontStyle': 'italic', 'color': '#6e7681', 'fontSize': '12px', 'padding': '6px 0'}
        )

    # Current CWE context element — тёмный
    current_title = f"CWE-{current_cwe}"
    current_desc = edge_texts.get(current_cwe, "Research Concepts Hierarchy Base Node.")
    context_element = [
        html.Div([
            html.Span("Current Level: ", style={
                'fontSize': '11px',
                'color': '#6e7681',
                'fontFamily': "'JetBrains Mono', monospace",
                'textTransform': 'uppercase',
                'letterSpacing': '0.5px'
            }),
            html.Span(current_title, style={
                'fontSize': '15px',
                'fontWeight': '700',
                'color': '#e67e22',
                'fontFamily': "'Montserrat', sans-serif",
                'marginLeft': '4px'
            })
        ], style={'marginBottom': '6px'}),
        html.P(current_desc, style={
            'fontSize': '13px',
            'color': '#8b949e',
            'fontStyle': 'italic',
            'margin': '0',
            'lineHeight': '1.5'
        })
    ]

    if len(history) > 1:
        parent_cwe = history[-2]
        back_style = {'display': 'inline-flex'}
        back_text = f"← CWE-{parent_cwe}"
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
    Output('radar-sidebar-prototypes', 'style'),
    Output('prototypes-collapse-btn', 'className'),
    Input('prototypes-collapse-btn', 'n_clicks'),
    State('radar-sidebar-prototypes', 'style'),
    prevent_initial_call=True
)
def toggle_prototypes_collapse(n_clicks, current_style):
    # Определяем текущее состояние по display
    is_hidden = (current_style or {}).get('display', 'none') == 'none'
    _base = {'maxHeight': '340px', 'overflowY': 'auto', 'overflowX': 'hidden', 'paddingRight': '4px', 'marginTop': '8px'}
    if is_hidden:
        return {**_base, 'display': 'block'}, 'collapsible-header active'
    return {**_base, 'display': 'none'}, 'collapsible-header'
