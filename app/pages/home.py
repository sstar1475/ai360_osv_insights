import dash
from dash import html, dcc, callback, Input, Output
import pandas as pd
import plotly.graph_objects as go

from app.app import df_report
from tools.metrics import (
    calc_staleness_index,
    calc_avg_unfixed_life,
    calc_integral_severity,
    calc_high_severity_ratio,
    calc_open_to_close_ratio,
    calc_risk_concentration,
    calc_mttr,
    calc_global_security_rating
)
from tools.config.chart import ECOSYSTEM_COLORS, TIMELINE_LAYOUT

dash.register_page(__name__, path='/', name='Home')


# ── Pre-calculate KPIs once at startup ────────────────────────────────────────
def _safe(fn, *args, default="—", **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return default


total_vulns      = df_report['vulnerability_id'].nunique() if 'vulnerability_id' in df_report.columns else 0
total_ecosystems = 4  # PyPI · npm · Maven · Go
total_packages   = df_report['package_name'].nunique() if 'package_name' in df_report.columns else 0

# Fix rate
import json

def _has_fix(ranges_data):
    if not ranges_data:
        return False
    try:
        import json
        ranges = json.loads(ranges_data) if isinstance(ranges_data, str) else ranges_data
        for r in (ranges or []):
            for e in (r.get('events') or []):
                if isinstance(e, dict) and 'fixed' in e:
                    return True
    except Exception:
        pass
    return False

try:
    fix_rate = round(df_report['affected_ranges'].apply(_has_fix).mean() * 100, 1)
except Exception:
    fix_rate = "—"

# Average CVSS score
def _get_avg_cvss(df):
    try:
        # Try numeric first
        numeric_scores = pd.to_numeric(df['vulnerability_severity_score'], errors='coerce')
        
        # Mapping for categorical if numeric is missing
        sev_map = {'CRITICAL': 9.5, 'HIGH': 8.0, 'MODERATE': 5.5, 'MEDIUM': 5.5, 'LOW': 2.0, 'NONE': 0.0}
        
        def fill_from_text(row):
            if pd.notna(row['vulnerability_severity_score']):
                try:
                    val = float(row['vulnerability_severity_score'])
                    if val >= 0: return val
                except: pass
            
            text_val = str(row['vulnerability_severity_text']).strip().upper() if pd.notna(row['vulnerability_severity_text']) else None
            return sev_map.get(text_val, np.nan)

        import numpy as np
        combined_scores = df.apply(fill_from_text, axis=1).dropna()
        return round(float(combined_scores.mean()), 1) if not combined_scores.empty else "—"
    except Exception:
        return "—"

avg_cvss = _get_avg_cvss(df_report)

# Metrics from DB
high_sev_ratio = _safe(calc_high_severity_ratio, df_report)
open_close     = _safe(calc_open_to_close_ratio, df_report)
staleness      = _safe(calc_staleness_index, df_report)
mttr           = _safe(calc_mttr, df_report)
integral       = _safe(calc_integral_severity, df_report)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt(val, suffix=""):
    if val == "—":
        return "—"
    if isinstance(val, float):
        return f"{val:.1f}{suffix}"
    if isinstance(val, int):
        return f"{val:,}{suffix}"
    return f"{val}{suffix}"


def kpi_card(value, label, sub=None, color='#e67e22', tag=None):
    return html.Div([
        html.Div(value, className='kpi-value kpi-animate', style={'color': color}),
        html.Div(label, className='kpi-label'),
        html.Div(sub or "", className='kpi-sub') if sub else html.Div(),
        html.Div(tag, style={
            'marginTop': '6px',
            'fontSize': '10px',
            'color': color,
            'background': f'rgba({_hex_to_rgb(color)},0.12)',
            'border': f'1px solid rgba({_hex_to_rgb(color)},0.3)',
            'borderRadius': '20px',
            'padding': '1px 8px',
            'display': 'inline-block',
            'fontFamily': "'JetBrains Mono', monospace",
            'letterSpacing': '0.5px'
        }) if tag else html.Div()
    ], className='kpi-card', style={'flex': '1', 'minWidth': '140px'})


def _hex_to_rgb(hex_color):
    h = hex_color.lstrip('#')
    return ','.join(str(int(h[i:i+2], 16)) for i in (0, 2, 4))


def nav_card(title, href, description):
    return html.Div([
        dcc.Link([
            html.Div([
                html.H2(title, className='card-header', style={
                    'fontSize': '17px',
                    'marginTop': '0',
                    'marginBottom': '10px'
                }),
                html.P(description, style={
                    'fontSize': '13px',
                    'color': '#8b949e',
                    'lineHeight': '1.5',
                    'margin': '0'
                })
            ])
        ], href=href, className='card-link')
    ], className='nav-card', style={
        'flex': '1',
        'minWidth': '220px',
        'maxWidth': '320px',
        'margin': '8px'
    })


# ── Callbacks ─────────────────────────────────────────────────────────────────

@callback(
    Output('home-gsr-graph', 'figure'),
    Input('home-gsr-ecosystem-dropdown', 'value')
)
def update_gsr_graph(selected_eco):
    ecosystems = ['PyPI', 'npm', 'Go', 'Maven']
    
    if selected_eco == 'All':
        display_list = ecosystems + ['All']
        height = 300
    else:
        display_list = [selected_eco]
        height = 140

    ratings = []
    colors = []
    labels = []

    for eco in display_list:
        if eco == 'All':
            filtered_df = df_report
            color = ECOSYSTEM_COLORS.get('All', '#8b949e')
            label = "Overall Rating"
        else:
            filtered_df = df_report[df_report['package_ecosystem'] == eco]
            color = ECOSYSTEM_COLORS.get(eco, '#e67e22')
            label = eco
        
        rating = calc_global_security_rating(filtered_df)
        ratings.append(rating)
        colors.append(color)
        labels.append(label)

    # Create figure
    fig = go.Figure(go.Bar(
        x=ratings,
        y=labels,
        orientation='h',
        marker=dict(
            color=colors,
            line=dict(color='#f0f6fc', width=1)
        ),
        text=[f"<b>{r}</b> / 100" for r in ratings],
        textposition='auto',
        textfont=dict(size=14, color='#f0f6fc', family='JetBrains Mono'),
        hovertemplate="Ecosystem: <b>%{y}</b><br>Rating: <b>%{x}</b>/100<extra></extra>"
    ))

    # Layout adjustment
    layout_cfg = dict(**TIMELINE_LAYOUT)
    layout_cfg['height'] = height
    layout_cfg['margin'] = dict(l=100, r=40, t=20, b=40)
    layout_cfg['xaxis'] = dict(
        range=[0, 105],
        gridcolor='#30363d',
        tickfont=dict(color='#8b949e'),
        title="Security Score"
    )
    layout_cfg['yaxis'] = dict(
        showgrid=False,
        autorange="reversed", # Show top down
        tickfont=dict(size=13, color='#f0f6fc', weight='bold')
    )
    
    fig.update_layout(**layout_cfg)
    return fig


# ── Layout ────────────────────────────────────────────────────────────────────
layout = html.Div([

    # ── Hero Section ──────────────────────────────────────────────────────────
    html.Div([
        html.Div([
            html.H1(
                "OSV Insights",
                className='hero-title',
                style={'fontSize': '60px', 'marginBottom': '12px', 'marginTop': '0'}
            ),
            html.P(
                "Anatomy of Vulnerabilities in Open Source Projects",
                className='hero-subtitle',
                style={'marginBottom': '16px'}
            ),
            html.Div([
                html.Span(f"{total_ecosystems} Ecosystems", style={
                    'color': '#58a6ff',
                    'fontFamily': "'JetBrains Mono', monospace",
                    'fontSize': '13px',
                    'marginRight': '16px'
                }),
                html.Span("·", style={'color': '#30363d', 'marginRight': '16px'}),
                html.Span(f"{total_vulns:,} CVEs · {total_packages:,} Packages", style={
                    'color': '#8b949e',
                    'fontFamily': "'JetBrains Mono', monospace",
                    'fontSize': '13px',
                }),
            ], style={'marginBottom': '40px'})
        ], style={'textAlign': 'center', 'paddingBottom': '40px'})
    ]),

    # ── KPI Strip ─────────────────────────────────────────────────────────────
    html.Div([
        kpi_card(f"{total_vulns:,}", "Vulnerabilities", "unique CVEs analyzed", '#e67e22', "CVE"),
        kpi_card(f"{fix_rate}%", "Fix Rate", "with a known patch", '#3fb950', "FIXED"),
        kpi_card(str(avg_cvss), "Avg CVSS", "mean severity score", '#eab308', "CVSS"),
        kpi_card(_fmt(staleness, "%"), "Staleness Index", "> 2 yrs unfixed", '#d97706', "M1"),
        kpi_card(_fmt(mttr, " days"), "Mean Time to Repair", "avg fix time", '#f85149', "M2"),
        kpi_card(_fmt(integral), "Integral Risk", "weighted severity", '#d2a8ff', "M3"),
        kpi_card(f"{high_sev_ratio}%" if high_sev_ratio != "—" else "—", "High/Critical", "unpatched ratio", '#f85149', "M4"),
        kpi_card(f"{open_close}x" if open_close != "—" else "—", "Open/Close", "debt ratio", '#58a6ff', "M7"),
    ], style={
        'display': 'flex',
        'flexWrap': 'wrap',
        'gap': '10px',
        'marginBottom': '48px',
        'padding': '0 4px'
    }),

    # ── Global Security Rating Section ────────────────────────────────────────
    html.Div([
        html.Div([
            html.Div([
                html.H3("Global Security Ecosystem Rating", style={
                    'fontFamily': "'Montserrat', sans-serif",
                    'fontSize': '22px',
                    'fontWeight': '700',
                    'margin': '0',
                    'color': '#f0f6fc'
                }),
                html.P("Holistic health score (0-100) based on severity, density and criticality.", style={
                    'color': '#8b949e', 'fontSize': '14px', 'margin': '4px 0 0 0'
                })
            ], style={'flex': '1'}),
            
            html.Div([
                dcc.Dropdown(
                    id='home-gsr-ecosystem-dropdown',
                    options=[
                        {'label': 'All Ecosystems', 'value': 'All'},
                        {'label': 'PyPI', 'value': 'PyPI'},
                        {'label': 'npm', 'value': 'npm'},
                        {'label': 'Go', 'value': 'Go'},
                        {'label': 'Maven', 'value': 'Maven'}
                    ],
                    value='All',
                    clearable=False,
                    searchable=False,
                    style={'width': '200px'}
                )
            ])
        ], style={
            'display': 'flex', 
            'alignItems': 'center', 
            'justifyContent': 'space-between',
            'marginBottom': '24px'
        }),

        dcc.Graph(
            id='home-gsr-graph',
            config={'displayModeBar': False},
            style={'height': '300px'}
        )
    ], style={
        'background': '#161b22',
        'border': '1px solid #30363d',
        'borderRadius': '16px',
        'padding': '32px',
        'marginBottom': '48px',
        'boxShadow': '0 4px 20px rgba(0,0,0,0.2)'
    }),

    # ── Divider ───────────────────────────────────────────────────────────────

    html.Div([
        html.Div(style={'flex': '1', 'height': '1px', 'background': '#30363d'}),
        html.Span("EXPLORE", style={
            'padding': '0 20px',
            'fontSize': '11px',
            'color': '#6e7681',
            'letterSpacing': '2px',
            'fontFamily': "'Montserrat', sans-serif",
            'fontWeight': '600'
        }),
        html.Div(style={'flex': '1', 'height': '1px', 'background': '#30363d'}),
    ], style={'display': 'flex', 'alignItems': 'center', 'marginBottom': '28px'}),

    # ── Navigation Cards ──────────────────────────────────────────────────────
    html.Div([
        nav_card(
            "Common Statistics", "/common",
            "Sankey flow diagrams, CWE mappings, and quarterly trends"
        ),
        nav_card(
            "Package Risk Analytics", "/packages",
            "Risk matrix, top vulnerable packages, severity breakdowns"
        ),
        nav_card(
            "Vulnerability Analysis", "/affections",
            "CWE radar drill-down, severity stacked bars, affection patterns"
        ),
        nav_card(
            "Timeline Analysis", "/timeline",
            "Quarterly trends, fixed vs unfixed growth, seasonal patterns"
        ),
        nav_card(
            "Terminology", "/terminology",
            "CVE, CWE, CVSS, OSV definitions and all metric formulas"
        ),
    ], style={
        'display': 'flex',
        'flexWrap': 'wrap',
        'justifyContent': 'center',
        'gap': '0'
    }),

    # ── Footer ────────────────────────────────────────────────────────────────
    html.Div([
        html.P([
            html.A(
                "Data sourced from Google OSV Database",
                href="https://google.github.io/osv.dev/",
                target="_blank",
                style={
                    'color': '#58a6ff',
                    'textDecoration': 'none',
                    'borderBottom': '1px solid rgba(88,166,255,0.3)',
                    'transition': 'color 0.2s'
                }
            ),
            html.Span(" · PostgreSQL · Plotly Dash", style={'color': '#6e7681'}),
        ], style={
            'fontSize': '12px',
            'fontFamily': "'JetBrains Mono', monospace",
            'textAlign': 'center',
            'marginTop': '60px',
            'paddingTop': '20px',
            'borderTop': '1px solid #21262d'
        })
    ])
])
