import pandas as pd
import plotly.graph_objects as go
from tools.config.chart import TOP_PACKAGES_LAYOUT, SEVERITY_COLORS


def build_top_packages_fig(df: pd.DataFrame, ecosystem: str, top_n: int = 15) -> go.Figure:
    subset = df[
        (df['package_ecosystem'] == ecosystem) &
        (df['vulnerability_id'].str.startswith('GHSA', na=False))
        ].copy()

    if subset.empty:
        return go.Figure().update_layout(title="No data available for this ecosystem")

    if 'has_fix' not in subset.columns:
        subset['has_fix'] = subset.get('affected_ranges', pd.Series(dtype=str)).astype(str).str.contains('fixed',
                                                                                                         case=False,
                                                                                                         na=False)

    subset['has_fix_numeric'] = subset['has_fix'].astype(int)
    subset['severity'] = subset.get('vulnerability_severity_text', 'UNKNOWN').replace({'MODERATE': 'MEDIUM'}).fillna(
        'UNKNOWN')

    severity_mapping = {'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH', 'CRITICAL': 'CRITICAL', 'UNKNOWN': 'UNKNOWN'}
    subset['severity'] = subset['severity'].map(lambda x: severity_mapping.get(str(x).upper(), 'UNKNOWN'))

    pkg_stats = subset.groupby('package_name').agg(
        unique_vulns=('vulnerability_id', 'nunique'),
        fix_rate=('has_fix_numeric', 'mean')
    ).reset_index()

    top_n_df = pkg_stats.nlargest(top_n, 'unique_vulns').sort_values('unique_vulns', ascending=True)
    top_packages_list = top_n_df['package_name'].tolist()

    if not top_packages_list:
        return go.Figure().update_layout(title="No data available")

    top_subset = subset[subset['package_name'].isin(top_packages_list)]
    segment_stats = top_subset.groupby(['package_name', 'severity'])['vulnerability_id'].nunique().reset_index(
        name='count')

    fig = go.Figure()
    severity_order = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    for sev in severity_order:
        sev_data = segment_stats[segment_stats['severity'] == sev]
        if sev_data.empty: continue

        sev_dict = dict(zip(sev_data['package_name'], sev_data['count']))
        x_values = [sev_dict.get(pkg, 0) for pkg in top_packages_list]

        if sum(x_values) > 0:
            fig.add_trace(go.Bar(
                y=top_packages_list,
                x=x_values,
                name=sev,
                orientation='h',
                marker_color=SEVERITY_COLORS.get(sev, '#bdc3c7'),
                marker_line=dict(color='white', width=1),
                # ДОБАВЛЕНЫ ЦИФРЫ ПРЯМО ВНУТРЬ БАРОВ ДЛЯ ЧИТАБЕЛЬНОСТИ:
                text=[str(v) if v > 0 else '' for v in x_values],
                textposition='inside',
                textfont=dict(size=13, color='white', weight='bold'),
                hovertemplate="<b>%{y}</b><br>Severity: " + sev + "<br>Count: %{x}<extra></extra>"
            ))

    # УЛУЧШЕННЫЕ АННОТАЦИИ FIX RATE (Процент справа от графика)
    for _, row in top_n_df.iterrows():
        fig.add_annotation(
            x=row['unique_vulns'],
            y=row['package_name'],
            text=f" {row['fix_rate'] * 100:.0f}%",
            showarrow=False,
            xanchor='left',
            font=dict(size=15, color='#2980b9', weight='bold', family="Montserrat, sans-serif")
        )

    fig.update_layout(**TOP_PACKAGES_LAYOUT)
    fig.update_layout(
        xaxis=dict(
            title=dict(text='Unique Vulnerabilities Count', font=dict(size=15, weight='bold', color='#34495e')),
            range=[0, top_n_df['unique_vulns'].max() * 1.15],
            tickfont=dict(size=14, color="#7f8c8d")
        ),
        height=400 + (top_n * 25) if top_n > 15 else 500,  # Немного увеличили базовую высоту строк
        yaxis=dict(
            title=None,
            # УВЕЛИЧЕНЫ И ВЫДЕЛЕНЫ НАЗВАНИЯ ПАКЕТОВ:
            tickfont=dict(size=15, color="#2c3e50", weight="bold", family="Montserrat, sans-serif")
        )
    )
    return fig
