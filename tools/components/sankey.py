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
    cwe_num = cwe_original.replace('CWE-', '').strip()
    desc = edge_texts.get(cwe_num, "Description unavailable")
    cwe_options.append({
        'label': f"CWE-{cwe_num} — {desc}",
        'value': cwe_original
    })

# Формируем список пакетов с префиксом экосистемы
pkg_options = []
if 'package_name' in df_report.columns and 'package_ecosystem' in df_report.columns:
    unique_pkgs_df = df_report[['package_ecosystem', 'package_name']].drop_duplicates().dropna()
    unique_pkgs_df = unique_pkgs_df[unique_pkgs_df['package_ecosystem'].isin(unique_ecosystems)]
    unique_pkgs_df = unique_pkgs_df.sort_values(by=['package_ecosystem', 'package_name'])
    for _, row in unique_pkgs_df.iterrows():
        eco = row['package_ecosystem']
        pkg = row['package_name']
        pkg_options.append({
            'label': f"{eco}: {pkg}",
            'value': f"{eco}::{pkg}"
        })

# Inline style shorthand для тёмных dropdown
_DD_STYLE = {
    'backgroundColor': '#1c2128',
    'color': '#f0f6fc',
    'border': '1px solid #30363d',
}
_LABEL_STYLE = {
    'fontWeight': '600',
    'color': '#f0f6fc',
    'marginBottom': '6px',
    'display': 'block',
    'fontSize': '13px',
    'fontFamily': "'Open Sans', sans-serif"
}


def create_sankey_chart() -> html.Div:
    return html.Div([
        html.H3(
            "Vulnerability Flow Analysis (Sankey)",
            id='sankey-collapse-btn',
            className='collapsible-header',
            style={'color': '#e67e22', 'marginTop': '0', 'fontFamily': "'Montserrat', sans-serif"}
        ),

        html.Div([
            html.P(
                "Trace vulnerability flows from CWE categories down to ecosystems and packages.",
                style={'color': '#8b949e', 'fontSize': '14px', 'marginBottom': '20px'}
            ),

            # Filter panel
            html.Div([
                # Row 1: Dropdowns + Min slider
                html.Div([
                    html.Div([
                        html.Label("CWE Grouping Level:", style=_LABEL_STYLE),
                        dcc.Dropdown(
                            id='sankey-cwe-level',
                            options=[
                                {'label': 'Group by first 3 digits', 'value': 'group3'},
                                {'label': 'Full CWE-ID', 'value': 'full'}
                            ],
                            value='group3', clearable=False,
                            style=_DD_STYLE
                        )
                    ], style={'width': '31%', 'display': 'inline-block', 'marginRight': '3%'}),

                    html.Div([
                        html.Label("Target Resolution:", style=_LABEL_STYLE),
                        dcc.Dropdown(
                            id='sankey-target',
                            options=[
                                {'label': 'Ecosystems Only', 'value': 'ecosystem'},
                                {'label': 'Specific Packages', 'value': 'package'}
                            ],
                            value='ecosystem', clearable=False,
                            style=_DD_STYLE
                        )
                    ], style={'width': '31%', 'display': 'inline-block', 'marginRight': '3%'}),

                    html.Div([
                        html.Label("Min Vulnerabilities per Link:", style=_LABEL_STYLE),
                        dcc.Slider(
                            id='sankey-min-count', min=1, max=50, step=1, value=1,
                            marks={1: '1', 10: '10', 25: '25', 50: '50'}
                        )
                    ], style={'width': '31%', 'display': 'inline-block', 'verticalAlign': 'bottom'})
                ], style={'marginBottom': '20px'}),

                # Row 2: CWE sources + Packages sliders
                html.Div([
                    html.Div([
                        html.Label("Max CWE Sources:", style=_LABEL_STYLE),
                        dcc.Slider(
                            id='sankey-top-cwes', min=1, max=30, step=1, value=10,
                            marks={1: '1', 10: '10', 20: '20', 30: '30'}
                        )
                    ], style={'width': '48%', 'display': 'inline-block', 'marginRight': '4%'}),

                    html.Div([
                        html.Label("Max Packages per Ecosystem:", style=_LABEL_STYLE),
                        dcc.Slider(
                            id='sankey-top-pkgs', min=1, max=20, step=1, value=5,
                            marks={1: '1', 5: '5', 10: '10', 20: '20'}
                        )
                    ], style={'width': '48%', 'display': 'inline-block'})
                ], style={'marginBottom': '20px'}),

                # Row 3: Multi-select filters
                html.Div([
                    html.Label("Filter Ecosystems (Leave blank for all):", style=_LABEL_STYLE),
                    dcc.Dropdown(
                        id='sankey-incl-eco',
                        options=[{'label': e, 'value': e} for e in unique_ecosystems],
                        value=[], multi=True,
                        placeholder="Select ecosystems...",
                        style={**_DD_STYLE, 'marginBottom': '10px'}
                    ),
                    html.Label("Filter Packages (Leave blank for all):", style=_LABEL_STYLE),
                    dcc.Dropdown(
                        id='sankey-incl-pkg',
                        options=pkg_options,
                        value=[], multi=True,
                        placeholder="Search packages (e.g., 'PyPI: requests')...",
                        style={**_DD_STYLE, 'marginBottom': '10px'}
                    ),
                    html.Label("Filter CWEs (Leave blank for all):", style=_LABEL_STYLE),
                    dcc.Dropdown(
                        id='sankey-incl-cwe',
                        options=cwe_options,
                        value=[], multi=True,
                        placeholder="Search CWEs by ID or keywords...",
                        style=_DD_STYLE
                    )
                ])

            ], style={
                'backgroundColor': '#21262d',
                'padding': '24px',
                'borderRadius': '12px',
                'border': '1px solid #30363d',
                'marginBottom': '20px'
            }),

            dcc.Graph(id='sankey-chart-graph', config={'displayModeBar': False}),

            # CWE Legend
            html.Div([
                html.Div(
                    "Displayed CWEs Legend (Click to toggle):",
                    id='sankey-legend-btn',
                    className='collapsible-header',
                    style={
                        'fontSize': '14px', 'fontWeight': 'bold',
                        'color': '#e67e22', 'marginBottom': '10px',
                        'fontFamily': "'Montserrat', sans-serif", 'cursor': 'pointer'
                    }
                ),
                html.Div(id='sankey-cwe-legend', className='collapsible-content collapsed')
            ])

        ], id='sankey-collapse-content', className='collapsible-content collapsed')

    ], style={'width': '100%', 'display': 'flex', 'flexDirection': 'column'})


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
def toggle_sankey_legend(n_clicks, current_class):
    if "collapsed" in current_class:
        return "collapsible-content", "collapsible-header active"
    return "collapsible-content collapsed", "collapsible-header"


@callback(
    Output('sankey-chart-graph', 'figure'),
    Output('sankey-cwe-legend', 'children'),
    Input('sankey-cwe-level', 'value'),
    Input('sankey-target', 'value'),
    Input('sankey-min-count', 'value'),
    Input('sankey-top-cwes', 'value'),
    Input('sankey-top-pkgs', 'value'),
    Input('sankey-incl-eco', 'value'),
    Input('sankey-incl-pkg', 'value'),
    Input('sankey-incl-cwe', 'value'),
)
def update_sankey(cwe_level, target, min_count, top_cwes, top_pkgs, incl_eco, incl_pkg, incl_cwe):
    fig, used_cwes = build_sankey_figure(
        df_report,
        cwe_level=cwe_level or 'group3',
        target=target or 'ecosystem',
        min_count=min_count or 1,
        top_cwes_count=top_cwes or 10,
        top_pkgs_per_eco=top_pkgs or 5,
        include_ecosystems=incl_eco or [],
        include_packages=incl_pkg or [],
        include_cwes=incl_cwe or [],
    )

    legend_elements = []
    for cwe in sorted(used_cwes):
        cwe_num = str(cwe).replace('CWE-', '').strip()
        desc = edge_texts.get(cwe_num, "Description unavailable")
        legend_elements.append(html.Div([
            html.Span(f"CWE-{cwe_num} ", style={'fontWeight': 'bold', 'color': '#58a6ff', 'fontFamily': "'JetBrains Mono', monospace"}),
            html.Span(f"— {desc}")
        ], style={'padding': '6px 0', 'borderBottom': '1px solid #30363d', 'fontSize': '13px', 'color': '#8b949e'}))

    if not legend_elements:
        legend_elements = [html.Div(
            "No CWEs currently displayed.",
            style={'fontStyle': 'italic', 'color': '#6e7681', 'padding': '10px 0', 'fontSize': '13px'}
        )]

    return fig, legend_elements
