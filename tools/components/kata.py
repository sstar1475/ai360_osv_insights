"""
tools/components/kata.py
КАТА — кот-маскот OSV Insights. Плавающий виджет в правом нижнем углу.
При наведении показывает рандомный security-факт или подсказку.
"""
import random
from dash import html, dcc, callback, Input, Output, State

_KATA_FACTS = [
    "🔴 CWE-79 (XSS) is the #1 most exploited weakness in npm packages.",
    "📊 37,503 vulnerability records analyzed in this dashboard.",
    "⏳ The average unfixed vulnerability lives for over 800 days.",
    "🔐 Only ~40% of OSV vulnerabilities have a known fix version.",
    "🎯 Top 5 packages account for a disproportionate share of all CVEs.",
    "📅 Vulnerability disclosures peak in Q1 and Q3 each year.",
    "🕸️ CWE-1000 Research Concepts view has 10 root pillars.",
    "⚡ CVSS ≥ 9.0 (Critical) vulns in PyPI grew 3× since 2019.",
    "🐍 PyPI has the fastest-growing vulnerability count since 2020.",
    "🔢 CVSS alone doesn't predict exploitability — check EPSS too!",
    "🛡️ Go ecosystem has the lowest staleness index of all 4 ecosystems.",
    "🧩 Maven (Java) dominates in CWE-502 (Deserialization) vulnerabilities.",
    "meow... 😺 I guard this dashboard from vulnerabilities!",
]


def create_kata_widget() -> html.Div:
    """Returns the КАТА floating cat widget."""
    return html.Div([
        # Hidden store for current fact index
        dcc.Store(id='kata-fact-idx', data=0),
        dcc.Interval(id='kata-interval', interval=8000, n_intervals=0),

        # The cat button
        html.Div([
            # Tooltip bubble
            html.Div(
                id='kata-bubble',
                children=_KATA_FACTS[0],
                style={
                    'position': 'absolute',
                    'bottom': '80px',
                    'right': '0',
                    'width': '260px',
                    'background': '#21262d',
                    'border': '1px solid #e67e22',
                    'borderRadius': '12px',
                    'padding': '12px 16px',
                    'fontSize': '13px',
                    'color': '#f0f6fc',
                    'lineHeight': '1.5',
                    'boxShadow': '0 4px 20px rgba(230,126,34,0.25)',
                    'display': 'none',
                    'fontFamily': "'Open Sans', sans-serif",
                    'zIndex': '9999',
                }
            ),
            # Cat emoji button
            html.Div(
                "🐱",
                id='kata-btn',
                n_clicks=0,
                title="Ката — охранник уязвимостей!",
                style={
                    'fontSize': '36px',
                    'cursor': 'pointer',
                    'lineHeight': '1',
                    'filter': 'drop-shadow(0 0 8px rgba(230,126,34,0.5))',
                    'transition': 'transform 0.2s ease, filter 0.2s ease',
                    'userSelect': 'none',
                }
            ),
            html.Div("КАТА", style={
                'fontFamily': "'Montserrat', sans-serif",
                'fontWeight': '700',
                'fontSize': '9px',
                'color': '#e67e22',
                'textAlign': 'center',
                'letterSpacing': '1px',
                'marginTop': '2px'
            })
        ], style={
            'position': 'relative',
            'textAlign': 'center'
        })
    ], id='kata-widget', style={
        'position': 'fixed',
        'bottom': '28px',
        'right': '28px',
        'zIndex': '9998',
        'cursor': 'pointer',
    })


@callback(
    Output('kata-bubble', 'style'),
    Output('kata-bubble', 'children'),
    Output('kata-fact-idx', 'data'),
    Input('kata-btn', 'n_clicks'),
    Input('kata-interval', 'n_intervals'),
    State('kata-fact-idx', 'data'),
    prevent_initial_call=True
)
def toggle_kata_bubble(n_clicks, n_intervals, fact_idx):
    from dash import ctx
    triggered = ctx.triggered_id

    base_style = {
        'position': 'absolute',
        'bottom': '80px',
        'right': '0',
        'width': '260px',
        'background': '#21262d',
        'border': '1px solid #e67e22',
        'borderRadius': '12px',
        'padding': '12px 16px',
        'fontSize': '13px',
        'color': '#f0f6fc',
        'lineHeight': '1.5',
        'boxShadow': '0 4px 20px rgba(230,126,34,0.25)',
        'fontFamily': "'Open Sans', sans-serif",
        'zIndex': '9999',
    }

    if triggered == 'kata-btn':
        # Toggle visibility + next fact
        new_idx = (fact_idx + 1) % len(_KATA_FACTS)
        if n_clicks % 2 == 1:
            return {**base_style, 'display': 'block'}, _KATA_FACTS[new_idx], new_idx
        else:
            return {**base_style, 'display': 'none'}, _KATA_FACTS[fact_idx], fact_idx

    # Auto-rotate fact when visible
    if triggered == 'kata-interval':
        new_idx = (fact_idx + 1) % len(_KATA_FACTS)
        return {**base_style, 'display': 'none'}, _KATA_FACTS[new_idx], new_idx

    return {**base_style, 'display': 'none'}, _KATA_FACTS[fact_idx], fact_idx
