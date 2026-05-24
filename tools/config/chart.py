METRIC_COLORS = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']

SEVERITY_COLORS = {
    'LOW': '#66bb6a',       # Зеленый
    'MEDIUM': '#2196F3',    # Синий
    'HIGH': '#9C27B0',      # Фиолетовый
    'CRITICAL': '#ef5350',  # Красный
    'UNKNOWN': '#bdbdbd'    # Серый
}

BASE_FONT = dict(family="Open Sans, sans-serif", size=14, color="#34495e")

# Общий шаблон (Layout) для радарной диаграммы
RADAR_LAYOUT = dict(
    polar=dict(
        domain=dict(x=[0, 1], y=[0, 1]),
        radialaxis=dict(
            visible=True,
            gridcolor="#e0e6ed",
            gridwidth=1.5,
            linecolor="#bdc3c7",
            tickfont=dict(size=14, color="#7f8c8d")
        ),
        angularaxis=dict(
            direction="clockwise",
            gridcolor="#e0e6ed",
            linecolor="#bdc3c7",
            tickfont=dict(size=16, color="#2c3e50", weight="bold")
        ),
        bgcolor="#fdfdfe"
    ),
    font=BASE_FONT,
    template="plotly_white",
    height=650,
    showlegend=True,
    legend=dict(
        orientation="h",
        yanchor="top",
        y=-0.15,
        xanchor="center",
        x=0.5,
        font=dict(size=16),    # Увеличен шрифт легенды радара (было 14)
        traceorder="normal"
    ),
    margin=dict(t=50, b=130, l=10, r=10)
)

# Шаблон (Layout) для Stacked Bar Chart
STACKED_BAR_LAYOUT = dict(
    barmode='stack',
    template='plotly_white',
    height=550,
    font=BASE_FONT,
    legend=dict(
        title_text='Severity Level',
        orientation='h',
        yanchor='bottom',
        y=1.02,
        xanchor='center',
        x=0.5,
        font=dict(size=16)    # Увеличен шрифт легенды гистограммы для консистентности
    ),
    hoverlabel=dict(bgcolor='white', font_size=13),
    margin=dict(t=60, b=60, l=60, r=40),
    paper_bgcolor="#fdfdfe",
    plot_bgcolor="#fdfdfe"
)

SANKEY_NODE_PALETTE = [
    '#00a8e8', '#007ea7', '#003459',
    '#ff9e00', '#ff8500', '#f77f00',
    '#023e8a', '#00509d', '#002855'
]

# Полупрозрачные цвета для связей (линков) на основе Severity
SANKEY_LINK_COLORS = {
    'CRITICAL': 'rgba(239, 83, 80, 0.4)',  # Мягкий красный
    'HIGH': 'rgba(156, 39, 176, 0.4)',     # Фиолетовый
    'MEDIUM': 'rgba(33, 150, 243, 0.4)',   # Синий
    'LOW': 'rgba(102, 187, 106, 0.4)',     # Зеленый
    'NONE': 'rgba(189, 189, 189, 0.3)',    # Серый
    'UNKNOWN': 'rgba(189, 189, 189, 0.3)'
}

# Шаблон (Layout) для Sankey Chart
SANKEY_LAYOUT = dict(
    template='plotly_white',
    height=650,
    font=BASE_FONT,
    margin=dict(t=40, b=40, l=40, r=40),
    paper_bgcolor="#fdfdfe",
    plot_bgcolor="#fdfdfe",
    hoverlabel=dict(bgcolor='white', font_size=13, font_family="Open Sans")
)
# Палитра для экосистем
ECOSYSTEM_COLORS = {
    'PyPI': '#377eb8',
    'npm': '#e41a1c',
    'Go': '#4daf4a',
    'Maven': '#984ea3',
    'All': '#7f8c8d'
}

# Шаблон для матрицы рисков
RISK_MATRIX_LAYOUT = dict(
    template="plotly_white",
    font=BASE_FONT,
    margin=dict(l=60, r=40, t=60, b=100), # Большой отступ снизу для легенды
    plot_bgcolor='#fdfdfe',
    paper_bgcolor='#fdfdfe',
    hovermode='closest',
    legend=dict(
        orientation="h",
        yanchor="top",
        y=-0.15,
        xanchor="center",
        x=0.5,
        font=dict(size=15)
    )
)

# Шаблон для Top Packages
TOP_PACKAGES_LAYOUT = dict(
    barmode='stack',
    template="plotly_white",
    font=BASE_FONT,
    margin=dict(l=150, r=50, t=50, b=80),
    plot_bgcolor='#fdfdfe',
    paper_bgcolor='#fdfdfe',
    legend=dict(
        orientation="h",
        yanchor="top",
        y=-0.12,
        xanchor="center",
        x=0.5,
        font=dict(size=15)
    )
)
