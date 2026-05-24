"""
tools/figures/timeline.py
Timeline analysis figures: quarterly trends, cumulative growth, seasonality bar.
"""
import pandas as pd
import plotly.graph_objects as go

from tools.config.chart import ECOSYSTEM_COLORS, TIMELINE_LAYOUT

_ALLOWED_ECOSYSTEMS = ['Go', 'Maven', 'PyPI', 'npm']


def build_quarterly_line(df: pd.DataFrame) -> go.Figure:
    """
    Line chart: new vulnerabilities per quarter (from 2016), ecosystems: Go/Maven/PyPI/npm only.
    """
    if df.empty or 'vulnerability_published' not in df.columns:
        return _empty_fig("No temporal data available")

    df = df.copy()
    df['vulnerability_published'] = pd.to_datetime(df['vulnerability_published'], errors='coerce', utc=True)
    df = df.dropna(subset=['vulnerability_published'])

    # Filter: only allowed ecosystems, from 2016
    df = df[df['package_ecosystem'].isin(_ALLOWED_ECOSYSTEMS)]
    df = df[df['vulnerability_published'].dt.year >= 2016]

    if df.empty:
        return _empty_fig("No data from 2016 for selected ecosystems")

    df['quarter'] = df['vulnerability_published'].dt.to_period('Q').dt.to_timestamp()

    timeline = (
        df.groupby(['quarter', 'package_ecosystem'])['vulnerability_id']
        .nunique()
        .reset_index(name='count')
    )

    fig = go.Figure()
    for eco in _ALLOWED_ECOSYSTEMS:
        sub = timeline[timeline['package_ecosystem'] == eco].sort_values('quarter')
        if sub.empty:
            continue
        color = ECOSYSTEM_COLORS.get(eco, '#8b949e')
        fig.add_trace(go.Scatter(
            x=sub['quarter'],
            y=sub['count'],
            name=eco,
            mode='lines+markers',
            line=dict(color=color, width=2.5),
            marker=dict(color=color, size=7, symbol='circle',
                        line=dict(color='#0d1117', width=1.5)),
            hovertemplate=(
                f"<b>{eco}</b><br>"
                "%{x|%Y Q%q}<br>"
                "New vulns: <b>%{y}</b><extra></extra>"
            )
        ))

    layout = dict(**TIMELINE_LAYOUT)
    layout['title'] = dict(
        text='New Vulnerabilities per Quarter (from 2016)',
        font=dict(size=16, color='#f0f6fc', family='Montserrat'),
        x=0.01
    )
    fig.update_layout(**layout)
    fig.update_xaxes(range=['2016-01-01', None])
    return fig


def build_cumulative_area(df: pd.DataFrame) -> go.Figure:
    """
    Area chart: fixed vs unfixed vulnerabilities by year (from 2015).
    """
    if df.empty or 'vulnerability_published' not in df.columns:
        return _empty_fig("No temporal data available")

    df = df.copy()
    df['vulnerability_published'] = pd.to_datetime(df['vulnerability_published'], errors='coerce', utc=True)
    df = df.dropna(subset=['vulnerability_published'])

    # Filter from 2015
    df = df[df['vulnerability_published'].dt.year >= 2015]
    df['year'] = df['vulnerability_published'].dt.year

    import json

    def has_fix(r):
        try:
            ranges = json.loads(r) if isinstance(r, str) else r
            for rng in (ranges or []):
                for e in (rng.get('events') or []):
                    if isinstance(e, dict) and 'fixed' in e:
                        return True
        except Exception:
            pass
        return False

    if 'affected_ranges' in df.columns:
        df['is_fixed'] = df['affected_ranges'].apply(has_fix)
    else:
        df['is_fixed'] = False

    total_by_year = df.groupby('year')['vulnerability_id'].nunique().reset_index(name='total')
    fixed_by_year = df[df['is_fixed']].groupby('year')['vulnerability_id'].nunique().reset_index(name='fixed')
    agg = total_by_year.merge(fixed_by_year, on='year', how='left').fillna(0)
    agg['unfixed'] = agg['total'] - agg['fixed']

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=agg['year'], y=agg['fixed'],
        name='Fixed', fill='tozeroy',
        line=dict(color='#3fb950', width=2),
        fillcolor='rgba(63,185,80,0.2)',
        mode='lines',
        hovertemplate="Year: %{x}<br>Fixed: <b>%{y}</b><extra></extra>"
    ))
    fig.add_trace(go.Scatter(
        x=agg['year'], y=agg['unfixed'],
        name='Unfixed', fill='tozeroy',
        line=dict(color='#f85149', width=2),
        fillcolor='rgba(248,81,73,0.15)',
        mode='lines',
        hovertemplate="Year: %{x}<br>Unfixed: <b>%{y}</b><extra></extra>"
    ))

    layout = dict(**TIMELINE_LAYOUT)
    layout['title'] = dict(
        text='Fixed vs Unfixed Vulnerabilities by Year (from 2015)',
        font=dict(size=16, color='#f0f6fc', family='Montserrat'),
        x=0.01
    )
    fig.update_layout(**layout)
    fig.update_xaxes(range=[2015, None])
    return fig


def build_seasonality_bar(df: pd.DataFrame) -> go.Figure:
    """Bar chart: vulnerability distribution by month of year (seasonality)."""
    if df.empty or 'vulnerability_published' not in df.columns:
        return _empty_fig("No temporal data available")

    df = df.copy()
    df['vulnerability_published'] = pd.to_datetime(df['vulnerability_published'], errors='coerce', utc=True)
    df = df.dropna(subset=['vulnerability_published'])
    df['month'] = df['vulnerability_published'].dt.month

    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    monthly = df.groupby('month')['vulnerability_id'].nunique().reindex(range(1, 13), fill_value=0)
    mean_val = monthly.mean()

    colors = ['#58a6ff' if v < mean_val else '#e67e22' for v in monthly.values]

    fig = go.Figure(go.Bar(
        x=month_names,
        y=monthly.values,
        marker_color=colors,
        marker_line_color='#30363d',
        marker_line_width=1,
        hovertemplate="Month: <b>%{x}</b><br>Vulnerabilities: <b>%{y}</b><extra></extra>"
    ))

    layout = dict(**TIMELINE_LAYOUT)
    layout['title'] = dict(
        text='Seasonal Distribution (Month of Year)',
        font=dict(size=16, color='#f0f6fc', family='Montserrat'),
        x=0.01
    )
    layout['showlegend'] = False
    layout['height'] = 350
    fig.update_layout(**layout)
    fig.add_hline(
        y=float(mean_val),
        line_dash='dot', line_color='#6e7681', line_width=1.5,
        annotation_text=f"  avg: {mean_val:.0f}",
        annotation_font_color='#8b949e', annotation_font_size=11
    )
    return fig


def _empty_fig(message: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, xref='paper', yref='paper', x=0.5, y=0.5,
                       showarrow=False, font=dict(size=16, color='#8b949e'))
    fig.update_layout(
        paper_bgcolor='#161b22', plot_bgcolor='#161b22',
        xaxis=dict(visible=False), yaxis=dict(visible=False)
    )
    return fig
