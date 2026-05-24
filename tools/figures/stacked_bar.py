import pandas as pd
import plotly.graph_objects as go

from tools.config.chart import STACKED_BAR_LAYOUT, SEVERITY_COLORS
from tools.cwe_parse.cwe_parse import CWENode
from tools.cwe_parse.PrototypeFilter import get_children
from tools.cwe_parse.XMLConfigure import get_cwe_info

CWE_PILLAR_CACHE = {}


def get_cwe_mapping() -> dict:
    """
    Динамически запрашиваем дочерние ветки CWE-1000 (Research Concepts) из XML-парсера
    и собираем всех их потомков для маппинга.
    """
    global CWE_PILLAR_CACHE
    if CWE_PILLAR_CACHE:
        return CWE_PILLAR_CACHE

    root_pillars = get_children("1000")
    cwe_descriptions = get_cwe_info()

    for p_id in root_pillars:
        clean_p_id = str(p_id).strip()
        description = cwe_descriptions.get(clean_p_id, "Unknown classification")

        if len(description) > 40:
            description = description[:37] + "..."

        label = f"CWE-{clean_p_id}<br><span style='font-size:12px; color:#7f8c8d; font-family: Open Sans, sans-serif'>{description}</span>"

        CWE_PILLAR_CACHE[f"CWE-{clean_p_id}"] = label
        CWE_PILLAR_CACHE[clean_p_id] = label

        try:
            descendants = CWENode(clean_p_id).get_descendants()
            for child_id in descendants:
                CWE_PILLAR_CACHE[f"CWE-{child_id}"] = label
                CWE_PILLAR_CACHE[str(child_id)] = label
        except Exception as e:
            print(f"Ошибка получения детей для CWE-{clean_p_id}: {e}")

    return CWE_PILLAR_CACHE


def build_stacked_bar_figure(df_source: pd.DataFrame, group_by: str = 'ecosystem',
                             normalized: bool = False) -> go.Figure:
    """Генерирует Plotly Figure для многослойной гистограммы."""
    data = df_source.copy()
    if data.empty:
        return go.Figure().update_layout(title="No data available")

    data = data[
        (data['vulnerability_id'].str.startswith('GHSA', na=False)) &
        (data['package_ecosystem'].isin(['PyPI', 'npm', 'Go', 'Maven']))
        ]

    data['severity'] = data['vulnerability_severity_text'].replace({'MODERATE': 'MEDIUM'}).fillna('UNKNOWN')

    severity_mapping = {'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH', 'CRITICAL': 'CRITICAL'}
    data['severity'] = data['severity'].map(lambda x: severity_mapping.get(str(x).upper(), 'UNKNOWN'))

    data = data[data['severity'] != 'UNKNOWN']

    if group_by == 'cwe_class':
        data['cwe_clean'] = data['vulnerability_cwe_id'].astype(str).str.split('|').str[0].str.strip()

        cwe_mapping = get_cwe_mapping()

        data['cwe_pillar'] = data['cwe_clean'].map(cwe_mapping).fillna('DROP_ME')

        data = data[data['cwe_pillar'] != 'DROP_ME']

        group_col = 'cwe_pillar'
    else:
        group_col = 'package_ecosystem'

    grouped = data.groupby([group_col, 'severity']).size().reset_index(name='count')
    grouped = grouped[grouped['count'] > 0]

    if normalized:
        totals = grouped.groupby(group_col)['count'].transform('sum')
        grouped['count'] = (grouped['count'] / totals) * 100

    group_order = grouped.groupby(group_col)['count'].sum().sort_values(ascending=False).index.tolist()

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
            marker_line=dict(color='white', width=1.5),
            text=[f'{v:.1f}%' if normalized and v > 3 else (f'{int(v):,}' if v > 0 else '') for v in y_values],
            textposition='inside',
            textfont=dict(size=14, color='white', weight='bold', family="Montserrat, sans-serif"),
            insidetextanchor='middle',
            hovertemplate="<b>%{x}</b><br>Severity: " + sev + "<br>Value: %{y:.1f}<extra></extra>"
        ))

    fig.update_layout(**STACKED_BAR_LAYOUT)

    fig.update_layout(
        xaxis=dict(
            title=None,
            categoryorder='array',
            categoryarray=group_order,
            tickfont=dict(size=15, color="#2c3e50", weight="bold", family="Montserrat, sans-serif"),
            tickangle=35 if group_by == 'cwe_class' else 0,
        ),
        yaxis=dict(
            title=dict(text='Percentage (%)' if normalized else 'Vulnerability Count',
                       font=dict(size=15, weight='bold', color="#34495e")),
            tickfont=dict(size=14, color="#7f8c8d"),
            ticksuffix='%' if normalized else '',
            gridcolor='#e0e6ed',
            gridwidth=1
        ),
        margin=dict(b=140)
    )

    return fig
