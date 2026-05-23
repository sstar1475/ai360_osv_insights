import pandas as pd
import plotly.graph_objects as go

from tools.config.chart import STACKED_BAR_LAYOUT, SEVERITY_COLORS
from tools.cwe_parse.cwe_parse import CWENode

CWE_PILLAR_CACHE = {}


def get_cwe_mapping() -> dict:
    """
    Детерминированно задаем 10 дочерних веток CWE-1000 (Research Concepts)
    и собираем всех их потомков.
    """
    global CWE_PILLAR_CACHE
    if CWE_PILLAR_CACHE:
        return CWE_PILLAR_CACHE

    # Хардкодим 10 главных Pillars и их человекочитаемые описания
    # Используем тег <br> для переноса строки на графике Plotly
    pillars = {
        "664": "Improper Control of a Resource",
        "707": "Improper Neutralization",
        "284": "Improper Access Control",
        "693": "Protection Mechanism Failure",
        "691": "Insufficient Control Flow",
        "710": "Coding Standards Violation",
        "703": "Improper Handling of Exceptions",
        "682": "Incorrect Calculation",
        "435": "Improper Interaction",
        "697": "Incorrect Comparison"
    }

    for p_id, description in pillars.items():
        # Формируем красивую подпись: "CWE-664\nImproper Control..."
        label = f"CWE-{p_id}<br><span style='font-size:10px; color:gray'>{description}</span>"

        # Записываем сам пиллар
        CWE_PILLAR_CACHE[f"CWE-{p_id}"] = label
        CWE_PILLAR_CACHE[str(p_id)] = label

        # Достаем всех потомков этого пиллара и мапим на ту же категорию
        try:
            descendants = CWENode(p_id).get_descendants()
            for child_id in descendants:
                CWE_PILLAR_CACHE[f"CWE-{child_id}"] = label
                CWE_PILLAR_CACHE[str(child_id)] = label
        except Exception as e:
            print(f"Ошибка получения детей для CWE-{p_id}: {e}")

    return CWE_PILLAR_CACHE


def build_stacked_bar_figure(df_source: pd.DataFrame, group_by: str = 'ecosystem',
                             normalized: bool = False) -> go.Figure:
    """Генерирует Plotly Figure для многослойной гистограммы."""
    data = df_source.copy()
    if data.empty:
        return go.Figure().update_layout(title="No data available")

    # Фильтруем данные: только GHSA и 4 целевые экосистемы
    data = data[
        (data['vulnerability_id'].str.startswith('GHSA', na=False)) &
        (data['package_ecosystem'].isin(['PyPI', 'npm', 'Go', 'Maven']))
        ]

    # ----- 1. Маппинг Severity -----
    data['severity'] = data['vulnerability_severity_text'].replace({'MODERATE': 'MEDIUM'}).fillna('UNKNOWN')
    severity_mapping = {'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH', 'CRITICAL': 'CRITICAL', 'UNKNOWN': 'UNKNOWN'}
    data['severity'] = data['severity'].map(lambda x: severity_mapping.get(str(x).upper(), 'UNKNOWN'))

    # ----- 2. Группировка -----
    if group_by == 'cwe_class':
        # Вытаскиваем чистый CWE ID
        data['cwe_clean'] = data['vulnerability_cwe_id'].astype(str).str.split('|').str[0].str.strip()

        cwe_mapping = get_cwe_mapping()

        # Маппим. Все, что не попало в наши 10 веток, становится 'DROP_ME'
        data['cwe_pillar'] = data['cwe_clean'].map(cwe_mapping).fillna('DROP_ME')

        # ВЫРЕЗАЕМ ВЕСЬ UNKNOWN / OTHER МУСОР ИЗ ДАТАФРЕЙМА
        data = data[data['cwe_pillar'] != 'DROP_ME']

        group_col = 'cwe_pillar'
    else:
        group_col = 'package_ecosystem'

    # ----- 3. Подсчёт -----
    grouped = data.groupby([group_col, 'severity']).size().reset_index(name='count')
    grouped = grouped[grouped['count'] > 0]

    if normalized:
        totals = grouped.groupby(group_col)['count'].transform('sum')
        grouped['count'] = (grouped['count'] / totals) * 100

    # ----- 4. Порядок столбцов (по убыванию суммы) -----
    group_order = grouped.groupby(group_col)['count'].sum().sort_values(ascending=False).index.tolist()

    # ----- 5. Сборка графика -----
    fig = go.Figure()
    severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    for sev in severity_order:
        sub = grouped[grouped['severity'] == sev]
        if sub.empty:
            continue
        sub_dict = dict(zip(sub[group_col], sub['count']))
        y_values = [sub_dict.get(g, 0) for g in group_order]

        fig.add_trace(go.Bar(
            name=sev,
            x=group_order,
            y=y_values,
            marker_color=SEVERITY_COLORS.get(sev, '#9e9e9e'),
            marker_line=dict(color='white', width=1),
            text=[f'{v:.1f}%' if normalized and v > 3 else (f'{int(v):,}' if v > 0 else '') for v in y_values],
            textposition='inside',
            textfont=dict(size=12, color='white', weight='bold'),
            insidetextanchor='middle',
            hovertemplate="<b>%{x}</b><br>Severity: " + sev + "<br>Value: %{y:.1f}<extra></extra>"
        ))

    # Применяем внешние стили из chart_theme.py
    fig.update_layout(**STACKED_BAR_LAYOUT)

    # Динамические настройки осей
    fig.update_layout(
        xaxis=dict(
            title=None,
            categoryorder='array',
            categoryarray=group_order,
            tickfont=dict(size=13, color="#2c3e50", weight="bold"),
            # Оставляем легкий наклон, если подписи сильно длинные
            tickangle=35 if group_by == 'cwe_class' else 0,
        ),
        yaxis=dict(
            title='Percentage (%)' if normalized else 'Vulnerability Count',
            ticksuffix='%' if normalized else '',
            gridcolor='#e0e6ed',
            gridwidth=1
        ),
        # Увеличиваем отступ снизу, чтобы влезли описания
        margin=dict(b=140)
    )

    return fig
