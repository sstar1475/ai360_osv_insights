# tools/components/sankey_layout.py
from dash import dcc, html, callback, Input, Output, State

from tools.figures.sankey import build_sankey_figure
from tools.cwe_parse.XMLConfigure import get_cwe_info
from app.app import df_report

# --- ПОДГОТОВКА ДАННЫХ ДЛЯ ВЫПАДАЮЩИХ СПИСКОВ ---
edge_texts = get_cwe_info()

unique_ecosystems = ['PyPI', 'Maven', 'npm', 'Go']

# Формируем список CWE с текстовыми описаниями для поиска
raw_cwes = df_report[
    'vulnerability_cwe_id'].dropna().unique().tolist() if 'vulnerability_cwe_id' in df_report.columns else []
cwe_options = []
for cwe in raw_cwes:
    cwe_original = str(cwe).strip()

    # Очищаем строку от префикса 'CWE-', чтобы получить чистый номер (например, '149')
    cwe_num = cwe_original.replace('CWE-', '').strip()

    # Ищем описание в словаре по чистому числовому ключу
    desc = edge_texts.get(cwe_num, "Description unavailable")

    cwe_options.append({
        'label': f"CWE-{cwe_num} — {desc}",
        'value': cwe_original  # Важно: сохраняем оригинальное значение (с префиксом) для корректной фильтрации в Pandas
    })

# Формируем список пакетов с префиксом экосистемы (PyPI: requests)
pkg_options = []
if 'package_name' in df_report.columns and 'package_ecosystem' in df_report.columns:
    unique_pkgs_df = df_report[['package_ecosystem', 'package_name']].drop_duplicates().dropna()
    unique_pkgs_df = unique_pkgs_df.sort_values(by=['package_ecosystem', 'package_name'])
    for _, row in unique_pkgs_df.iterrows():
        eco = row['package_ecosystem']
        pkg = row['package_name']
        pkg_options.append({
            'label': f"{eco}: {pkg}",
            'value': f"{eco}::{pkg}"  # Value содержит разделитель '::' для фильтрации в sankey_fig.py
        })


def create_sankey_chart() -> html.Div:
    return html.Div([
        html.H3(
            "Vulnerability Flow Analysis (Sankey)",
            id='sankey-collapse-btn',
            className='collapsible-header',
            style={'color': '#e67e22', 'marginTop': '0', 'fontFamily': "'Montserrat', sans-serif"}
        ),

        html.Div([
            html.P("Trace the flow of vulnerabilities from CWE categories down to specific ecosystems and packages.",
                   style={'color': '#7f8c8d', 'fontSize': '16px', 'marginBottom': '25px'}),

            html.Div([
                html.Div([
                    html.Div([
                        html.Label("CWE Grouping Level:",
                                   style={'fontWeight': '600', 'color': '#2c3e50', 'marginBottom': '5px',
                                          'display': 'block'}),
                        dcc.Dropdown(
                            id='sankey-cwe-level',
                            options=[{'label': 'Group by first 3 digits', 'value': 'group3'},
                                     {'label': 'Full CWE-ID', 'value': 'full'}],
                            value='group3', clearable=False
                        )
                    ], style={'width': '31%', 'display': 'inline-block', 'marginRight': '3%'}),

                    html.Div([
                        html.Label("Target Resolution:",
                                   style={'fontWeight': '600', 'color': '#2c3e50', 'marginBottom': '5px',
                                          'display': 'block'}),
                        dcc.Dropdown(
                            id='sankey-target',
                            options=[{'label': 'Ecosystems Only', 'value': 'ecosystem'},
                                     {'label': 'Specific Packages', 'value': 'package'}],
                            value='ecosystem', clearable=False
                        )
                    ], style={'width': '31%', 'display': 'inline-block', 'marginRight': '3%'}),

                    html.Div([
                        html.Label("Min Vulnerabilities per Link:",
                                   style={'fontWeight': '600', 'color': '#2c3e50', 'marginBottom': '5px',
                                          'display': 'block'}),
                        dcc.Slider(
                            id='sankey-min-count',
                            min=1, max=50, step=1, value=1,
                            marks={1: '1', 10: '10', 25: '25', 50: '50'}
                        )
                    ], style={'width': '31%', 'display': 'inline-block', 'verticalAlign': 'bottom'})
                ], style={'marginBottom': '20px'}),

                html.Div([
                    html.Div([
                        html.Label("Max CWE Sources:",
                                   style={'fontWeight': '600', 'color': '#2c3e50', 'marginBottom': '5px',
                                          'display': 'block'}),
                        dcc.Slider(
                            id='sankey-top-cwes',
                            min=1, max=30, step=1, value=10,
                            marks={1: '1', 10: '10', 20: '20', 30: '30'}
                        )
                    ], style={'width': '48%', 'display': 'inline-block', 'marginRight': '4%'}),

                    html.Div([
                        html.Label("Max Packages per Ecosystem:",
                                   style={'fontWeight': '600', 'color': '#2c3e50', 'marginBottom': '5px',
                                          'display': 'block'}),
                        dcc.Slider(
                            id='sankey-top-pkgs',
                            min=1, max=20, step=1, value=5,
                            marks={1: '1', 5: '5', 10: '10', 20: '20'}
                        )
                    ], style={'width': '48%', 'display': 'inline-block'})
                ], style={'marginBottom': '20px'}),

                # Выпадающие списки с новым форматом
                html.Div([
                    html.Label("Filter Ecosystems (Leave blank for all):",
                               style={'fontWeight': '600', 'color': '#2c3e50', 'fontSize': '13px'}),
                    dcc.Dropdown(
                        id='sankey-incl-eco',
                        options=[{'label': e, 'value': e} for e in unique_ecosystems],
                        value=[], multi=True, placeholder="Select ecosystems...", style={'marginBottom': '10px'}
                    ),
                    html.Label("Filter Packages (Leave blank for all):",
                               style={'fontWeight': '600', 'color': '#2c3e50', 'fontSize': '13px'}),
                    dcc.Dropdown(
                        id='sankey-incl-pkg',
                        options=pkg_options,  # Используем склеенный список
                        value=[], multi=True, placeholder="Search packages (e.g., 'PyPI: requests')...",
                        style={'marginBottom': '10px'}
                    ),
                    html.Label("Filter CWEs (Leave blank for all):",
                               style={'fontWeight': '600', 'color': '#2c3e50', 'fontSize': '13px'}),
                    dcc.Dropdown(
                        id='sankey-incl-cwe',
                        options=cwe_options,  # Используем список с описаниями
                        value=[], multi=True, placeholder="Search CWEs by ID or keywords..."
                    )
                ])

            ], style={'backgroundColor': '#f8f9fa', 'padding': '25px', 'borderRadius': '12px',
                      'border': '1px solid #ecf0f1', 'marginBottom': '20px'}),

            dcc.Graph(
                id='sankey-chart-graph',
                config={'displayModeBar': False}
            ),

            # --- НОВЫЙ БЛОК: Легенда CWE под графиком ---
            html.Div([
                html.Div("Displayed CWEs Legend (Click to toggle):",
                         id='sankey-legend-btn',
                         className='collapsible-header',
                         style={'fontSize': '16px', 'fontWeight': 'bold', 'color': '#e67e22', 'marginBottom': '15px',
                                'fontFamily': "'Montserrat', sans-serif", 'cursor': 'pointer'}),

                html.Div(id='sankey-cwe-legend', className='collapsible-content collapsed')
            ], className='cwe-sidebar-card', style={'marginTop': '20px'})

        ], id='sankey-collapse-content', className='collapsible-content collapsed')

    ], style={'width': '100%', 'display': 'flex', 'flexDirection': 'column'})


# --- АНИМАЦИИ СВОРАЧИВАНИЯ ---
@callback(
    Output('sankey-collapse-content', 'className'),
    Output('sankey-collapse-btn', 'className'),
    Input('sankey-collapse-btn', 'n_clicks'),
    State('sankey-collapse-content', 'className'),
    prevent_initial_call=True
)
def toggle_sankey_collapse(n_clicks, current_class):
    if "collapsed" in current_class:
        return "collapsible-content", "collapsible-header active"
    return "collapsible-content collapsed", "collapsible-header"


@callback(
    Output('sankey-cwe-legend', 'className'),
    Output('sankey-legend-btn', 'className'),
    Input('sankey-legend-btn', 'n_clicks'),
    State('sankey-cwe-legend', 'className'),
    prevent_initial_call=True
)
def toggle_sankey_legend_collapse(n_clicks, current_class):
    if "collapsed" in current_class:
        return "collapsible-content", "collapsible-header active"
    return "collapsible-content collapsed", "collapsible-header"


# --- ИНТЕРАКТИВНОСТЬ И РЕНДЕР ЛЕГЕНДЫ ---
@callback(
    Output('sankey-chart-graph', 'figure'),
    Output('sankey-cwe-legend', 'children'),  # Новый Output для легенды
    [
        Input('sankey-cwe-level', 'value'),
        Input('sankey-target', 'value'),
        Input('sankey-min-count', 'value'),
        Input('sankey-top-cwes', 'value'),
        Input('sankey-top-pkgs', 'value'),
        Input('sankey-incl-eco', 'value'),
        Input('sankey-incl-pkg', 'value'),
        Input('sankey-incl-cwe', 'value')
    ]
)
def update_sankey_interactivity(cwe_level, target, min_count, top_cwes, top_pkgs, incl_eco, incl_pkg, incl_cwe):
    # Получаем график и список задействованных CWE
    fig, used_cwes = build_sankey_figure(
        df_report, cwe_level, target, min_count, top_cwes,
        top_pkgs, incl_cwe, incl_eco, incl_pkg
    )

    # Генерируем HTML-легенду
    legend_elements = []
    for cwe in sorted(used_cwes):
        # Вычленяем чистый ID (например, '079' -> '79')
        cwe_id = str(cwe).replace('CWE-', '').lstrip('0') or '0'
        desc = edge_texts.get(cwe_id, "Description unavailable.")

        legend_elements.append(html.Div([
            html.Span(f"{cwe} ", style={'fontWeight': 'bold', 'color': '#2980b9'}),
            html.Span(f"— {desc}")
        ], style={'padding': '8px 0', 'borderBottom': '1px solid #ecf0f1', 'fontSize': '14px', 'color': '#34495e'}))

    if not legend_elements:
        legend_elements = [html.Div("No CWEs are currently displayed on the graph.",
                                    style={'fontStyle': 'italic', 'color': '#7f8c8d'})]

    return fig, legend_elements
