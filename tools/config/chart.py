METRIC_COLORS = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']

BASE_FONT = dict(family="Open Sans, sans-serif", size=14, color="#34495e")

# Общий шаблон (Layout) для радарной диаграммы
RADAR_LAYOUT = dict(
    polar=dict(
        domain=dict(
            x=[0, 0.52],  # Сузили радар до 52%, отдавая правую половину под длинные тексты
            y=[0, 1]
        ),
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
    height=750, # Увеличили высоту для больших списков
    showlegend=True,
    legend=dict(
        orientation="v",
        yanchor="top",
        y=0.28,                # Сильно опустили легенду под список прототипов
        xanchor="left",
        x=0.58,                # Сдвинули все правые элементы к отметке 58% ширины
        font=dict(size=15),    # Сделали шрифт легенды еще крупнее
        traceorder="normal"
    ),
    margin=dict(t=50, b=50, l=20, r=20)
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

BASE_FONT = dict(family="Open Sans, sans-serif", size=14, color="#34495e")

# Общий шаблон (Layout) для радарной диаграммы
RADAR_LAYOUT = dict(
    polar=dict(
        domain=dict(
            x=[0, 0.58],  # Слегка сузили радар для большего простора справа
            y=[0, 1]
        ),
        radialaxis=dict(
            visible=True,
            gridcolor="#e0e6ed",
            gridwidth=1.5,
            linecolor="#bdc3c7",
            tickfont=dict(size=13, color="#7f8c8d")
        ),
        angularaxis=dict(
            direction="clockwise",
            gridcolor="#e0e6ed",
            linecolor="#bdc3c7",
            tickfont=dict(size=15, color="#2c3e50", weight="bold")
        ),
        bgcolor="#fdfdfe"
    ),
    font=BASE_FONT,
    template="plotly_white",
    height=650,
    showlegend=True,
    legend=dict(
        orientation="v",       # Вертикальная легенда
        yanchor="top",         # Привязка легенды к её верхней точке
        y=0.38,                # Сместили легенду вниз, оставляя верхнюю часть для CWE
        xanchor="left",
        x=0.62,                # Выравнивание по левой границе правого блока
        font=dict(size=13),
        traceorder="normal"
    ),
    margin=dict(t=40, b=40, l=20, r=20)
)
