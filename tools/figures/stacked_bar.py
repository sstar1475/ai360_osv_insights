import pandas as pd
import plotly.graph_objects as go

from tools.config.chart import STACKED_BAR_LAYOUT, SEVERITY_COLORS


def build_stacked_bar_figure(df_source: pd.DataFrame, group_by: str = 'ecosystem',
                             normalized: bool = False) -> go.Figure:
    data = df_source.copy()
    if data.empty:
        return go.Figure().update_layout(title="No data available")

    data = data[
        (data['vulnerability_id'].str.startswith('GHSA', na=False)) &
        (data['package_ecosystem'].isin(['PyPI', 'npm', 'Go', 'Maven']))
        ]

    # ----- 1. Маппинг Severity -----
    data['severity'] = data['vulnerability_severity_text'].replace({'MODERATE': 'MEDIUM'}).fillna('UNKNOWN')
    severity_mapping = {'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH', 'CRITICAL': 'CRITICAL'}
    data['severity'] = data['severity'].map(lambda x: severity_mapping.get(str(x).upper(), 'UNKNOWN'))

    # СТРОГОЕ ИСКЛЮЧЕНИЕ НЕИЗВЕСТНЫХ СТАТУСОВ
    data = data[data['severity'] != 'UNKNOWN']

    # ----- 2. Группировка -----
    if group_by == 'cwe_class':
        data['cwe_first'] = data['vulnerability_cwe_id'].astype(str).str.split('|').str[0].str.strip()
        data['cwe_pillar'] = data['cwe_first'].str.extract(r'(\d)')[0].fillna('?')

        pillar_names = {
            '1': 'Architecture & Design', '2': 'Data Handling', '3': 'Control Flow',
            '4': 'Resource Management', '5': 'Protection Mechanism', '6': 'Time & State',
            '7': 'API / Interactions', '8': 'Code Quality', '9': 'Environment', '0': 'Other'
        }
        data['cwe_pillar'] = data['cwe_pillar'].map(pillar_names).fillna('?: Unknown / Other')
        group_col = 'cwe_pillar'
    else:
        group_col = 'package_ecosystem'

    # ----- 3. Подсчёт -----
    grouped = data.groupby([group_col, 'severity']).size().reset_index(name='count')
    grouped = grouped[grouped['count'] > 0]

    if normalized:
        totals = grouped.groupby(group_col)['count'].transform('sum')
        grouped['count'] = (grouped['count'] / totals) * 100

    group_order = grouped.groupby(group_col)['count'].sum().sort_values(ascending=False).index.tolist()

    # ----- 4. Сборка столбцов -----
    fig = go.Figure()
    severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']  # UNKNOWN полностью удален

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

    fig.update_layout(**STACKED_BAR_LAYOUT)

    fig.update_layout(
        xaxis=dict(
            title=None,
            categoryorder='array',
            categoryarray=group_order,
            tickfont=dict(size=14, color="#2c3e50", weight="bold")
        ),
        yaxis=dict(
            title='Percentage (%)' if normalized else 'Vulnerability Count',
            ticksuffix='%' if normalized else '',
            gridcolor='#e0e6ed',
            gridwidth=1
        )
    )

    return fig
