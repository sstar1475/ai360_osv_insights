import dash
from dash import html, dcc, callback, Input, Output, State
import pandas as pd

from tools.components.sankey import create_sankey_chart
from app.app import df_report

dash.register_page(__name__, path='/common', name='Common Statistics')

_PAGE_STYLE = {'color': '#f0f6fc', 'fontFamily': "'Open Sans', sans-serif"}

_CARD_STYLE = {
    'background': '#161b22',
    'border': '1px solid #30363d',
    'borderRadius': '16px',
    'padding': '28px',
    'marginBottom': '24px'
}


def _build_year_bar():
    """Bar chart: vulnerabilities by year, from 2014."""
    try:
        import plotly.graph_objects as go
        from tools.config.chart import TIMELINE_LAYOUT

        df = df_report.copy()
        df['year'] = pd.to_datetime(
            df['vulnerability_published'], errors='coerce', utc=True
        ).dt.year
        year_counts = (
            df.groupby('year')['vulnerability_id']
            .nunique()
            .reset_index(name='count')
        )
        year_counts = year_counts.dropna(subset=['year'])
        year_counts = year_counts[year_counts['year'] >= 2014]   # From 2014

        # Color bars: orange for recent (>=2020), blue for older
        colors = [
            '#e67e22' if y >= 2020 else '#58a6ff'
            for y in year_counts['year'].astype(int)
        ]

        fig = go.Figure(go.Bar(
            x=year_counts['year'].astype(int),
            y=year_counts['count'],
            marker_color=colors,
            marker_line_color='#30363d',
            marker_line_width=1,
            hovertemplate="Year: <b>%{x}</b><br>Unique CVEs: <b>%{y}</b><extra></extra>"
        ))
        layout = dict(**TIMELINE_LAYOUT)
        layout['height'] = 340
        layout['showlegend'] = False
        layout['title'] = dict(
            text='Vulnerabilities by Year (from 2014)',
            font=dict(size=15, color='#f0f6fc', family='Montserrat'),
            x=0.01
        )
        layout['xaxis'] = dict(
            gridcolor='#30363d', linecolor='#30363d',
            tickfont=dict(color='#8b949e'),
            dtick=1, tickangle=-45
        )
        layout['yaxis'] = dict(
            gridcolor='#30363d', linecolor='#30363d',
            tickfont=dict(color='#8b949e')
        )
        fig.update_layout(**layout)
        return fig
    except Exception as e:
        import plotly.graph_objects as go
        fig = go.Figure()
        fig.add_annotation(
            text=f"Error: {e}", xref='paper', yref='paper',
            x=0.5, y=0.5, showarrow=False, font=dict(color='#8b949e')
        )
        fig.update_layout(paper_bgcolor='#161b22', plot_bgcolor='#161b22')
        return fig


year_fig = _build_year_bar()

layout = html.Div([
    html.H1(
        "Common Statistics",
        style={
            'textAlign': 'center',
            'fontFamily': "'Montserrat', sans-serif",
            'fontSize': '38px',
            'fontWeight': '700',
            'marginBottom': '8px',
            'color': '#f0f6fc'
        }
    ),
    html.P(
        "Vulnerability flows, CWE categories, and yearly distribution.",
        style={
            'textAlign': 'center',
            'color': '#8b949e',
            'fontSize': '15px',
            'marginBottom': '40px'
        }
    ),

    # Sankey (existing)
    html.Div(create_sankey_chart(), style=_CARD_STYLE),

    # Year distribution chart (from 2014, NO heatmap)
    html.Div([
        html.H3(
            "Vulnerability Distribution by Year",
            id='year-chart-btn',
            className='collapsible-header',
            style={'marginTop': '0'}
        ),
        html.Div([
            html.P(
                "Total unique CVEs disclosed per calendar year across all ecosystems. "
                "Blue = 2014–2019, Orange = 2020+.",
                style={'color': '#8b949e', 'fontSize': '14px', 'marginBottom': '20px'}
            ),
            dcc.Graph(
                id='year-dist-graph',
                figure=year_fig,
                config={'displayModeBar': False}
            )
        ], id='year-chart-content', className='collapsible-content collapsed')
    ], style=_CARD_STYLE),

], style=_PAGE_STYLE)


@callback(
    Output('year-chart-content', 'className'),
    Output('year-chart-btn', 'className'),
    Input('year-chart-btn', 'n_clicks'),
    State('year-chart-content', 'className'),
    prevent_initial_call=True
)
def toggle_year_chart(n, cls):
    return (('collapsible-content', 'collapsible-header active')
            if 'collapsed' in cls
            else ('collapsible-content collapsed', 'collapsible-header'))
