import dash
from dash import html, dcc
import pandas as pd

from app.app import df_report
from tools.metrics import (
    calc_staleness_index,
    calc_avg_unfixed_life,
    calc_integral_severity,
    calc_high_severity_ratio,
    calc_open_to_close_ratio,
    calc_risk_concentration,
)

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
import json, functools

def _has_fix(ranges_data):
    if not ranges_data:
        return False
    try:
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
try:
    scores = pd.to_numeric(df_report['vulnerability_severity_score'], errors='coerce').dropna()
    avg_cvss = round(float(scores.mean()), 1) if not scores.empty else "—"
except Exception:
    avg_cvss = "—"

# Metrics from DB
high_sev_ratio = _safe(calc_high_severity_ratio, df_report)
open_close     = _safe(calc_open_to_close_ratio, df_report)
staleness      = _safe(calc_staleness_index, df_report)
mttr           = _safe(calc_avg_unfixed_life, df_report)
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
        kpi_card(_fmt(mttr, " d"), "MTtR", "mean time to repair", '#f85149', "M2"),
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
            "Sankey flow diagrams and yearly vulnerability distribution"
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
