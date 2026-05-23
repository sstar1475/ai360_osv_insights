import dash
from dash import html

dash.register_page(__name__, path='/terminology', name='Terminology')

h2_style = {
    'color': '#e67e22',
    'fontFamily': "'Montserrat', sans-serif",
    'fontSize': '24px',
    'marginTop': '0',
    'marginBottom': '10px'
}

p_style = {
    'color': '#34495e',
    'fontFamily': "'Open Sans', sans-serif",
    'fontSize': '16px',
    'lineHeight': '1.6',
    'marginBottom': '35px'
}

image_card_style = {
    'backgroundColor': '#ffffff',
    'boxShadow': '0 6px 20px rgba(0, 0, 0, 0.06)',
    'borderRadius': '16px',
    'padding': '30px',
    'boxSizing': 'border-box',
    'textAlign': 'center'
}

layout = html.Div([
    html.H1(
        "Terminology & Guidelines",
        style={
            'textAlign': 'center',
            'color': '#2c3e50',
            'fontFamily': "'Montserrat', sans-serif",
            'fontSize': '38px',
            'fontWeight': '700',
            'marginBottom': '50px'
        }
    ),

    html.Div([
        # Левая колонка с терминами
        html.Div([
            html.H2("Base Concepts", style=h2_style),
            html.P(
                "Здесь будет располагаться подробное описание графа MITRE, архитектуры DAG и основных абстракций, таких как Pillar, Class и Base. Это фундаментальные понятия для понимания структуры уязвимостей.",
                style=p_style),

            html.H2("Metrics Definition", style=h2_style),
            html.P(
                "Описание математических моделей: экспоненциальная шкала Severity (2^(S-1)), логарифмическое сглаживание Patch Gap, функции Integral Severity Score и коэффициент затухания.",
                style=p_style),

            html.H2("Google OSV Database Usage Policy", style=h2_style),
            html.P(
                "Правила работы с дампом OSV, ограничения API, политики кэширования и обновления данных через SSH-туннель.",
                style=p_style),
        ], style={'flex': '1', 'paddingRight': '50px'}),

        # Правая колонка с GIF-анимацией и цитатой
        html.Div([
            html.Div([
                html.H3("Иллюстрация к терминам",
                        style={'color': '#2980b9', 'fontFamily': "'Montserrat', sans-serif", 'marginTop': '0'}),

                # Обновленный текст подзаголовка в виде мудрости
                html.P(
                    "Ага, вы поверили)",
                    style={
                        'color': '#7f8c8d',
                        'fontStyle': 'italic',
                        'fontSize': '16px',
                        'lineHeight': '1.5',
                        'marginTop': '15px',
                        'marginBottom': '15px'
                    }
                ),

                html.Img(
                    src="https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExMXhpNzV3NmppM3J3Z3dkdDIyaWFpbnBodjV0Nnd0aDJlM3UwaGdnNiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/KbdF8DCgaoIVC8BHTK/giphy.gif",
                    style={
                        'width': '100%'
                    }
                )
            ], style=image_card_style)
        ], style={'flex': '1', 'maxWidth': '500px'})

    ], style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'flex-start', 'maxWidth': '1100px',
              'margin': '0 auto'})
])
