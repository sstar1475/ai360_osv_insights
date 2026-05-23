# tools/figures/sankey_fig.py
import pandas as pd
import plotly.graph_objects as go

from tools.config.chart import SANKEY_LAYOUT, SANKEY_NODE_PALETTE, SANKEY_LINK_COLORS


def _empty_figure(text: str) -> tuple[go.Figure, list]:
    """Возвращает пустой график и пустой список CWE."""
    fig = go.Figure()
    fig.add_annotation(text=text, xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
                       font=dict(size=16, color="#7f8c8d"))
    fig.update_layout(height=400, template="plotly_white", paper_bgcolor="#fdfdfe")
    return fig, []


def build_sankey_figure(
        df_report: pd.DataFrame,
        cwe_level: str = 'group3',
        target: str = 'ecosystem',
        min_count: int = 1,
        top_cwes_count: int = 10,
        top_pkgs_per_eco: int = 5,
        include_cwes: list = None,
        include_ecosystems: list = None,
        include_packages: list = None
) -> tuple[go.Figure, list]:
    data = df_report.copy()
    include_cwes = include_cwes or []
    include_ecosystems = include_ecosystems or []
    include_packages = include_packages or []

    # 1. Фильтрация
    if 'vulnerability_id' in data.columns:
        data = data[data['vulnerability_id'].astype(str).str.startswith('GHSA', na=False)]

    allowed_ecosystems = ['PyPI', 'Maven', 'npm', 'Go']
    if 'package_ecosystem' in data.columns:
        data = data[data['package_ecosystem'].isin(allowed_ecosystems)]
        if include_ecosystems:
            data = data[data['package_ecosystem'].isin(include_ecosystems)]

    # НОВАЯ ЛОГИКА ФИЛЬТРАЦИИ ПАКЕТОВ: Ищем точное совпадение "Экосистема::Пакет"
    if include_packages and 'package_name' in data.columns:
        data['eco_pkg_combo'] = data['package_ecosystem'] + "::" + data['package_name']
        data = data[data['eco_pkg_combo'].isin(include_packages)]

    data['cwe_id'] = data.get('vulnerability_cwe_id', 'Unknown').fillna('Unknown')
    if include_cwes:
        data = data[data['cwe_id'].isin(include_cwes)]

    if data.empty:
        return _empty_figure("No data available for the selected filters.")

    # 2. Подготовка колонок
    data['severity'] = data.get('vulnerability_severity_text', 'UNKNOWN').fillna('UNKNOWN').astype(str).str.upper()
    data['cwe_num'] = data['cwe_id'].astype(str).str.extract(r'(\d+)').fillna('0').astype(str)

    if cwe_level == 'group3':
        data['cwe_source'] = data['cwe_num'].str.zfill(3).str[:3]
    else:
        data['cwe_source'] = 'CWE-' + data['cwe_num']

    nodes_labels = []
    node_indices = {}

    def get_node_idx(name, category):
        key = f"{category}_{name}"
        if key not in node_indices:
            node_indices[key] = len(nodes_labels)
            nodes_labels.append(str(name))
        return node_indices[key]

    source_indices, target_indices, values, link_colors, hover_labels = [], [], [], [], []
    used_cwes = []  # Список для легенды

    # 3. Агрегация данных
    if target == 'ecosystem':
        grouped = data.groupby(['cwe_source', 'package_ecosystem', 'severity']).size().reset_index(name='count')
        link_totals = grouped.groupby(['cwe_source', 'package_ecosystem'])['count'].sum().reset_index()
        valid = link_totals[link_totals['count'] >= min_count]
        grouped = grouped.merge(valid[['cwe_source', 'package_ecosystem']], on=['cwe_source', 'package_ecosystem'])

        top_cwes = grouped.groupby('cwe_source')['count'].sum().nlargest(top_cwes_count).index
        grouped = grouped[grouped['cwe_source'].isin(top_cwes)]

        if grouped.empty:
            return _empty_figure("No data available (Min count threshold not met).")

        used_cwes = grouped['cwe_source'].unique().tolist()  # Запоминаем попавшие в график CWE

        for _, row in grouped.iterrows():
            source_indices.append(get_node_idx(row['cwe_source'], 'cwe'))
            target_indices.append(get_node_idx(row['package_ecosystem'], 'eco'))
            values.append(row['count'])
            link_colors.append(SANKEY_LINK_COLORS.get(row['severity'], 'rgba(158, 158, 158, 0.3)'))
            hover_labels.append(
                f"{row['cwe_source']} → {row['package_ecosystem']}<br>Severity: {row['severity']}<br>Volume: {row['count']}")

    else:
        grouped = data.groupby(['cwe_source', 'package_name', 'package_ecosystem', 'severity']).size().reset_index(
            name='count')
        link_totals = grouped.groupby(['cwe_source', 'package_name'])['count'].sum().reset_index()
        valid = link_totals[link_totals['count'] >= min_count]
        grouped = grouped.merge(valid[['cwe_source', 'package_name']], on=['cwe_source', 'package_name'])

        if grouped.empty:
            return _empty_figure("No data available (Min count threshold not met).")

        pkg_totals = grouped.groupby(['package_ecosystem', 'package_name'])['count'].sum().reset_index()
        top_pkgs_df = pkg_totals.groupby('package_ecosystem', group_keys=False).apply(
            lambda x: x.nlargest(top_pkgs_per_eco, 'count'))
        grouped = grouped[grouped['package_name'].isin(top_pkgs_df['package_name'])]

        top_cwes = grouped.groupby('cwe_source')['count'].sum().nlargest(top_cwes_count).index
        grouped = grouped[grouped['cwe_source'].isin(top_cwes)]

        if grouped.empty:
            return _empty_figure("No data available after top-nodes filtering.")

        used_cwes = grouped['cwe_source'].unique().tolist()  # Запоминаем попавшие в график CWE

        cwe_pkg = grouped.groupby(['cwe_source', 'package_name', 'severity'])['count'].sum().reset_index()
        for _, row in cwe_pkg.iterrows():
            source_indices.append(get_node_idx(row['cwe_source'], 'cwe'))
            target_indices.append(get_node_idx(row['package_name'], 'pkg'))
            values.append(row['count'])
            link_colors.append(SANKEY_LINK_COLORS.get(row['severity'], 'rgba(158, 158, 158, 0.3)'))
            hover_labels.append(
                f"{row['cwe_source']} → {row['package_name']}<br>Severity: {row['severity']}<br>Volume: {row['count']}")

        pkg_eco = grouped.groupby(['package_name', 'package_ecosystem', 'severity'])['count'].sum().reset_index()
        for _, row in pkg_eco.iterrows():
            source_indices.append(get_node_idx(row['package_name'], 'pkg'))
            target_indices.append(get_node_idx(row['package_ecosystem'], 'eco'))
            values.append(row['count'])
            link_colors.append(SANKEY_LINK_COLORS.get(row['severity'], 'rgba(158, 158, 158, 0.3)'))
            hover_labels.append(
                f"{row['package_name']} → {row['package_ecosystem']}<br>Severity: {row['severity']}<br>Volume: {row['count']}")

    # 4. Сборка графика
    node_colors = []
    for name in nodes_labels:
        if any(key.startswith('cwe_') and name in key for key in node_indices):
            node_colors.append(SANKEY_NODE_PALETTE[0])
        elif any(key.startswith('pkg_') and name in key for key in node_indices):
            node_colors.append(SANKEY_NODE_PALETTE[3])
        else:
            node_colors.append(SANKEY_NODE_PALETTE[6])

    fig = go.Figure(data=[go.Sankey(
        arrangement="snap",
        node=dict(
            pad=20, thickness=15, line=dict(color="#ffffff", width=1),
            label=nodes_labels, color=node_colors, hoverlabel=dict(bgcolor="white")
        ),
        link=dict(
            source=source_indices, target=target_indices, value=values,
            color=link_colors, customdata=hover_labels, hovertemplate='%{customdata}<extra></extra>'
        )
    )])

    fig.update_layout(**SANKEY_LAYOUT)

    return fig, used_cwes
