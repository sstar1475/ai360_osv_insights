# tools/config/chart.py
# Dark Cybersecurity Theme — все цвета Plotly layout

METRIC_COLORS = ['#58a6ff', '#e67e22', '#3fb950', '#f85149', '#d2a8ff', '#ffa657']

SEVERITY_COLORS = {
    'LOW':      '#3fb950',
    'MEDIUM':   '#eab308',
    'HIGH':     '#d97706',
    'CRITICAL': '#f85149',
    'UNKNOWN':  '#6e7681'
}

_DARK_BG   = '#161b22'
_DARK_SURF = '#21262d'
_DARK_GRID = '#30363d'
_TEXT_PRIM = '#f0f6fc'
_TEXT_MUTE = '#8b949e'
_ACCENT    = '#e67e22'

BASE_FONT = dict(family="Open Sans, sans-serif", size=14, color=_TEXT_PRIM)

# ---- Radar Chart ----
RADAR_LAYOUT = dict(
    polar=dict(
        domain=dict(x=[0, 1], y=[0, 1]),
        radialaxis=dict(
            visible=True,
            gridcolor=_DARK_GRID,
            gridwidth=1.5,
            linecolor=_DARK_GRID,
            tickfont=dict(size=13, color=_TEXT_MUTE),
        ),
        angularaxis=dict(
            direction="clockwise",
            gridcolor=_DARK_GRID,
            linecolor=_DARK_GRID,
            tickfont=dict(size=15, color=_TEXT_PRIM, weight="bold")
        ),
        bgcolor=_DARK_SURF
    ),
    font=BASE_FONT,
    template="plotly_dark",
    height=650,
    showlegend=True,
    legend=dict(
        orientation="h",
        yanchor="top",
        y=-0.15,
        xanchor="center",
        x=0.5,
        font=dict(size=15, color=_TEXT_PRIM),
        traceorder="normal",
        bgcolor="rgba(22, 27, 34, 1.0)",
        bordercolor=_DARK_GRID,
        borderwidth=1
    ),
    hoverlabel=dict(
        bgcolor="rgba(13, 17, 23, 1.0)",
        font_size=14,
        font_family="JetBrains Mono, monospace",
        font_color=_TEXT_PRIM,
        bordercolor=_DARK_GRID
    ),
    hoverdistance=50,
    spikedistance=50,
    paper_bgcolor=_DARK_BG,
    plot_bgcolor=_DARK_SURF,
    margin=dict(t=50, b=130, l=10, r=10)
)

# ---- Stacked Bar Chart ----
STACKED_BAR_LAYOUT = dict(
    barmode='stack',
    template='plotly_dark',
    height=550,
    font=BASE_FONT,
    legend=dict(
        title_text='Severity Level',
        orientation='h',
        yanchor='bottom',
        y=1.02,
        xanchor='center',
        x=0.5,
        font=dict(size=15, color=_TEXT_PRIM),
        bgcolor="rgba(22, 27, 34, 1.0)",
        bordercolor=_DARK_GRID,
        borderwidth=1
    ),
    hoverlabel=dict(
        bgcolor="rgba(13, 17, 23, 1.0)",
        font_size=14,
        font_family="JetBrains Mono, monospace",
        font_color=_TEXT_PRIM,
        bordercolor=_DARK_GRID
    ),
    hoverdistance=50,
    spikedistance=50,
    margin=dict(t=60, b=60, l=60, r=40),
    paper_bgcolor=_DARK_BG,
    plot_bgcolor=_DARK_SURF,
    xaxis=dict(gridcolor=_DARK_GRID, linecolor=_DARK_GRID, tickfont=dict(color=_TEXT_MUTE)),
    yaxis=dict(gridcolor=_DARK_GRID, linecolor=_DARK_GRID, tickfont=dict(color=_TEXT_MUTE))
)

# ---- Sankey ----
SANKEY_NODE_PALETTE = [
    '#58a6ff', '#3fb950', '#e67e22', '#d2a8ff', '#ffa657',
    '#79c0ff', '#56d364', '#f0883e', '#bc8cff', '#ffb86c'
]

SANKEY_LINK_COLORS = {
    'CRITICAL': 'rgba(248, 81, 73, 0.8)',
    'HIGH':     'rgba(217, 119, 6, 0.8)',
    'MEDIUM':   'rgba(234, 179, 8, 0.7)',
    'LOW':      'rgba(63, 185, 80, 0.7)',
    'NONE':     'rgba(110, 118, 129, 0.6)',
    'UNKNOWN':  'rgba(110, 118, 129, 0.6)'
}

SANKEY_LAYOUT = dict(
    template='plotly_dark',
    height=650,
    font=BASE_FONT,
    margin=dict(t=40, b=40, l=40, r=40),
    paper_bgcolor=_DARK_BG,
    plot_bgcolor=_DARK_BG,
    hoverlabel=dict(
        bgcolor="rgba(13, 17, 23, 1.0)",
        font_size=14,
        font_family="JetBrains Mono, monospace",
        font_color=_TEXT_PRIM,
        bordercolor=_DARK_GRID
    )
)

# ---- Ecosystem Colors ----
ECOSYSTEM_COLORS = {
    'PyPI':   '#58a6ff',
    'npm':    '#f85149',
    'Go':     '#3fb950',
    'Maven':  '#d2a8ff',
    'All':    '#8b949e'
}

# ---- Risk Matrix ----
RISK_MATRIX_LAYOUT = dict(
    template="plotly_dark",
    font=BASE_FONT,
    margin=dict(l=60, r=40, t=60, b=100),
    plot_bgcolor=_DARK_SURF,
    paper_bgcolor=_DARK_BG,
    hovermode='closest',
    hoverlabel=dict(
        bgcolor="rgba(13, 17, 23, 1.0)",
        font_size=14,
        font_family="JetBrains Mono, monospace",
        font_color=_TEXT_PRIM,
        bordercolor=_DARK_GRID
    ),
    hoverdistance=50,
    spikedistance=50,
    xaxis=dict(gridcolor=_DARK_GRID, linecolor=_DARK_GRID, tickfont=dict(color=_TEXT_MUTE)),
    yaxis=dict(gridcolor=_DARK_GRID, linecolor=_DARK_GRID, tickfont=dict(color=_TEXT_MUTE)),
    legend=dict(
        orientation="h",
        yanchor="top",
        y=-0.15,
        xanchor="center",
        x=0.5,
        font=dict(size=14, color=_TEXT_PRIM),
        bgcolor="rgba(22, 27, 34, 1.0)",
        bordercolor=_DARK_GRID,
        borderwidth=1
    )
)

# ---- Top Packages ----
TOP_PACKAGES_LAYOUT = dict(
    barmode='stack',
    template="plotly_dark",
    font=BASE_FONT,
    margin=dict(l=180, r=50, t=50, b=80),
    plot_bgcolor=_DARK_SURF,
    paper_bgcolor=_DARK_BG,
    hoverlabel=dict(
        bgcolor="rgba(13, 17, 23, 1.0)",
        font_size=14,
        font_family="JetBrains Mono, monospace",
        font_color=_TEXT_PRIM,
        bordercolor=_DARK_GRID
    ),
    hoverdistance=50,
    spikedistance=50,
    xaxis=dict(gridcolor=_DARK_GRID, linecolor=_DARK_GRID, tickfont=dict(color=_TEXT_MUTE)),
    yaxis=dict(gridcolor=_DARK_GRID, linecolor=_DARK_GRID, tickfont=dict(color=_TEXT_MUTE)),
    legend=dict(
        orientation="h",
        yanchor="top",
        y=-0.12,
        xanchor="center",
        x=0.5,
        font=dict(size=14, color=_TEXT_PRIM),
        bgcolor="rgba(22, 27, 34, 1.0)",
        bordercolor=_DARK_GRID,
        borderwidth=1
    )
)

# ---- Timeline ----
TIMELINE_LAYOUT = dict(
    template="plotly_dark",
    font=BASE_FONT,
    height=420,
    margin=dict(l=60, r=30, t=50, b=60),
    plot_bgcolor=_DARK_SURF,
    paper_bgcolor=_DARK_BG,
    hovermode='x unified',
    hoverlabel=dict(
        bgcolor="rgba(13, 17, 23, 1.0)",
        font_size=14,
        font_family="JetBrains Mono, monospace",
        font_color=_TEXT_PRIM,
        bordercolor=_DARK_GRID
    ),
    hoverdistance=80,
    spikedistance=80,
    xaxis=dict(gridcolor=_DARK_GRID, linecolor=_DARK_GRID, tickfont=dict(color=_TEXT_MUTE)),
    yaxis=dict(gridcolor=_DARK_GRID, linecolor=_DARK_GRID, tickfont=dict(color=_TEXT_MUTE)),
    legend=dict(
        orientation="h",
        yanchor="top",
        y=1.12,
        xanchor="center",
        x=0.5,
        font=dict(size=13, color=_TEXT_PRIM),
        bgcolor="rgba(22, 27, 34, 1.0)",
        bordercolor=_DARK_GRID,
        borderwidth=1
    )
)

# ---- Heatmap ----
HEATMAP_LAYOUT = dict(
    template="plotly_dark",
    font=BASE_FONT,
    height=420,
    margin=dict(l=160, r=60, t=50, b=80),
    paper_bgcolor=_DARK_BG,
    plot_bgcolor=_DARK_SURF,
    hoverlabel=dict(
        bgcolor="rgba(13, 17, 23, 1.0)",
        font_size=14,
        font_family="JetBrains Mono, monospace",
        font_color=_TEXT_PRIM,
        bordercolor=_DARK_GRID
    ),
    hoverdistance=50,
    xaxis=dict(tickfont=dict(color=_TEXT_PRIM, size=13), linecolor=_DARK_GRID),
    yaxis=dict(tickfont=dict(color=_TEXT_PRIM, size=12), linecolor=_DARK_GRID)
)
