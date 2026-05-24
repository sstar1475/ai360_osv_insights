"""
tools/components/kpi_strip.py
Reusable KPI cards strip for analytics pages.
"""
from dash import html
import pandas as pd


def _safe_call(fn, df, **kwargs):
    try:
        return fn(df, **kwargs)
    except Exception:
        return None


def _fmt_val(val, suffix="", precision=1):
    if val is None:
        return "—"
    if isinstance(val, float):
        return f"{val:.{precision}f}{suffix}"
    return f"{val}{suffix}"


def _kpi(label, value, sub=None, color='#e67e22'):
    return html.Div([
        html.Div(value, style={
            'fontFamily': "'Montserrat', sans-serif",
            'fontWeight': '800',
            'fontSize': '26px',
            'color': color,
            'lineHeight': '1.1',
            'marginBottom': '2px'
        }),
        html.Div(label, style={
            'fontSize': '11px',
            'fontWeight': '600',
            'color': '#6e7681',
            'textTransform': 'uppercase',
            'letterSpacing': '0.8px'
        }),
        html.Div(sub or '', style={
            'fontSize': '11px',
            'color': '#6e7681',
            'fontFamily': "'JetBrains Mono', monospace",
            'marginTop': '2px'
        })
    ], style={
        'flex': '1',
        'minWidth': '130px',
        'background': '#161b22',
        'border': '1px solid #30363d',
        'borderRadius': '10px',
        'padding': '16px 20px',
        'textAlign': 'center',
        'transition': 'all 0.25s ease',
    }, className='kpi-card')


def create_affections_kpis(df: pd.DataFrame) -> html.Div:
    """KPI strip for Vulnerability & Affections Analysis page."""
    from tools.metrics import (
        calc_integral_severity,
        calc_staleness_index,
        calc_mttr,
        calc_high_severity_ratio,
        calc_open_to_close_ratio,
    )

    integral  = _safe_call(calc_integral_severity, df)
    staleness = _safe_call(calc_staleness_index, df)
    mttr      = _safe_call(calc_mttr, df)
    high_ratio= _safe_call(calc_high_severity_ratio, df)
    oc_ratio  = _safe_call(calc_open_to_close_ratio, df)

    return html.Div([
        _kpi("Integral Risk Score", _fmt_val(integral), "weighted severity", color='#f85149'),
        _kpi("Staleness Index", _fmt_val(staleness, "%"), "> 2 yrs unfixed", color='#d97706'),
        _kpi("Mean Time to Repair", _fmt_val(mttr, " days", 0), "avg fix time", color='#eab308'),
        _kpi("High/Critical Ratio", _fmt_val(high_ratio, "%"), "of all vulns", color='#f85149'),
        _kpi("Open / Close Ratio", _fmt_val(oc_ratio, "x"), "debt accumulation", color='#d2a8ff'),
    ], style={
        'display': 'flex',
        'flexWrap': 'wrap',
        'gap': '10px',
        'marginBottom': '28px'
    })


def create_packages_kpis(df: pd.DataFrame) -> html.Div:
    """KPI strip for Package Risk Analytics page."""
    from tools.metrics import (
        calc_defect_density,
        calc_risk_concentration,
        calc_open_to_close_ratio,
        calc_high_severity_ratio,
    )

    density = _safe_call(calc_defect_density, df)
    concentration = _safe_call(calc_risk_concentration, df)
    oc_ratio = _safe_call(calc_open_to_close_ratio, df)
    high_ratio = _safe_call(calc_high_severity_ratio, df)

    total_packages = df['package_name'].nunique() if 'package_name' in df.columns else 0

    return html.Div([
        _kpi("Total Packages", f"{total_packages:,}", "unique packages", color='#58a6ff'),
        _kpi("Defect Density", _fmt_val(density), "vulns per package", color='#e67e22'),
        _kpi("Risk Concentration", _fmt_val(concentration, "%"), "top-5 packages share", color='#f85149'),
        _kpi("Open / Close Ratio", _fmt_val(oc_ratio, "x"), "unfixed / fixed", color='#d2a8ff'),
        _kpi("High/Critical", _fmt_val(high_ratio, "%"), "of total vulns", color='#d97706'),
    ], style={
        'display': 'flex',
        'flexWrap': 'wrap',
        'gap': '10px',
        'marginBottom': '28px'
    })
