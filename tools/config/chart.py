METRIC_COLORS = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']

# Базовый шрифт приложения
BASE_FONT = dict(family="Open Sans, sans-serif", size=18, color="#34495e")

# Общий шаблон для Радарной диаграммы
RADAR_LAYOUT = dict(
    polar=dict(
        domain=dict(x=[0, 0.65], y=[0, 1]),
        radialaxis=dict(
            visible=True,
            gridcolor="#e0e6ed",
            gridwidth=1.5,
            linecolor="#bdc3c7",
            tickfont=dict(size=15, color="#7f8c8d")
        ),
        angularaxis=dict(
            direction="clockwise",
            gridcolor="#e0e6ed",
            linecolor="#bdc3c7",
            tickfont=dict(size=17, color="#2c3e50", weight="bold")
        ),
        bgcolor="#fdfdfe"
    ),
    font=BASE_FONT,
    template="plotly_white",
    height=650,
    showlegend=True,
    legend=dict(
        orientation="v",
        yanchor="middle",
        y=0.5,
        xanchor="left",
        x=0.7,
        font=dict(size=18)
    ),
    margin=dict(t=40, b=40, l=20, r=20)
)

SEVERITY_COLORS = {
    'LOW': '#66bb6a',       # Зеленый
    'MEDIUM': '#2196F3',    # Синий
    'HIGH': '#9C27B0',      # Фиолетовый
    'CRITICAL': '#ef5350',  # Красный
    'UNKNOWN': '#bdbdbd'    # Серый
}

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
        font=dict(size=14)
    ),
    hoverlabel=dict(bgcolor='white', font_size=13),
    margin=dict(t=60, b=60, l=60, r=40),
    paper_bgcolor="#fdfdfe",
    plot_bgcolor="#fdfdfe"
)
