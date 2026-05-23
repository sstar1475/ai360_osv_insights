# pages/common.py
#!/usr/bin/env python3.13
import dash
from dash import html

dash.register_page(__name__, path='/common', name='Common Statistics')

# Единый стиль для плейсхолдеров графиков (в виде красивых белых карточек с тенью)
placeholder_card_style = {
    'width': '46%',
    'minHeight': '280px',
    'backgroundColor': '#ffffff',
    'boxShadow': '0 6px 20px rgba(0, 0, 0, 0.06)',
    'borderRadius': '16px',
    'padding': '20px',
    'boxSizing': 'border-box',
    'display': 'flex',
    'alignItems': 'center',
    'justifyContent': 'center',
    'color': '#95a5a6', # Приглушенный серо-голубой для текста плейсхолдера
    'fontFamily': "'Open Sans', sans-serif",
    'fontSize': '18px',
    'fontStyle': 'italic',
    'border': '2px dashed #ecf0f1' # Легкая пунктирная рамка внутри карточки
}

# Общий контейнер для сетки на Flexbox
grid_container_style = {
    'display': 'flex',
    'flexWrap': 'wrap',
    'justifyContent': 'center',
    'gap': '30px', # Расстояние между карточками
    'width': '100%',
    'padding': '10px'
}

layout = html.Div([
    html.H1(
        "Common Statistics", 
        style={
            'textAlign': 'center', 
            'color': '#2c3e50', 
            'fontFamily': "'Montserrat', sans-serif",
            'fontSize': '38px',
            'fontWeight': '700',
            'marginBottom': '50px'
        }
    ),

    # Сетка для графиков
    html.Div([
        html.Div("Здесь будет первый график...", style=placeholder_card_style),
        html.Div("А здесь второй...", style=placeholder_card_style),
        html.Div("Место для круговой диаграммы...", style=placeholder_card_style),
        html.Div("Гистограмма распределения...", style=placeholder_card_style),
        html.Div("График динамики...", style=placeholder_card_style),
        html.Div("Дополнительная метрика...", style=placeholder_card_style),
    ], style=grid_container_style)
])
