import pandas as pd
import plotly.graph_objects as go
from tools.config.chart import RISK_MATRIX_LAYOUT, ECOSYSTEM_COLORS


def build_risk_matrix_fig(df: pd.DataFrame, min_vulns: int = 10, selected_ecosystem: str = 'All') -> go.Figure:
    subset = df[
        (df['vulnerability_id'].str.startswith('GHSA', na=False)) &
        (df['package_ecosystem'].isin(['PyPI', 'npm', 'Go', 'Maven']))
        ].copy()

    if selected_ecosystem != 'All':
        subset = subset[subset['package_ecosystem'] == selected_ecosystem]

    if subset.empty:
        return go.Figure().update_layout(title="No data available")

    if 'has_fix' not in subset.columns:
        subset['has_fix'] = subset.get('affected_ranges', pd.Series(dtype=str)).astype(str).str.contains('fixed',
                                                                                                         case=False,
                                                                                                         na=False)

    subset['has_fix_numeric'] = subset['has_fix'].astype(int)
    subset['severity'] = subset.get('vulnerability_severity_text', 'UNKNOWN').replace({'MODERATE': 'MEDIUM'}).fillna(
        'UNKNOWN')
    subset = subset[subset['severity'].isin(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])]

    severity_map = {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.5, 'LOW': 2.5}
    subset['cvss_num'] = subset['severity'].map(severity_map)

    pkg_stats = subset.groupby(['package_name', 'package_ecosystem']).agg(
        avg_cvss=('cvss_num', 'mean'),
        fix_rate=('has_fix_numeric', 'mean'),
        count=('vulnerability_id', 'nunique')
    ).reset_index()

    pkg_stats = pkg_stats[pkg_stats['count'] >= min_vulns]

    if pkg_stats.empty:
        return go.Figure().update_layout(title=f"No packages with >= {min_vulns} vulnerabilities")

    fig = go.Figure()
    ecosystems_to_plot = ['PyPI', 'npm', 'Go', 'Maven'] if selected_ecosystem == 'All' else [selected_ecosystem]

    max_count = pkg_stats['count'].max()
    desired_max_size = 75
    bubble_sizeref = 2. * max_count / (desired_max_size ** 2) if max_count > 0 else 1

    for eco in ecosystems_to_plot:
        eco_data = pkg_stats[pkg_stats['package_ecosystem'] == eco]
        if eco_data.empty: continue

        fig.add_trace(go.Scatter(
            x=eco_data['avg_cvss'],
            y=eco_data['fix_rate'] * 100,
            mode='markers',
            name=eco,
            marker=dict(
                color=ECOSYSTEM_COLORS.get(eco, '#333333'),
                size=eco_data['count'], sizemode='area', sizeref=bubble_sizeref, sizemin=8,
                line=dict(width=1, color='white'), opacity=0.75
            ),
            text=[
                f"<b>{n}</b><br>Ecosystem: {eco}<br>Avg CVSS: {c:.1f}<br>Fix Rate: {f * 100:.0f}%<br>Vulnerabilities: {cnt}"
                for n, c, f, cnt in
                zip(eco_data['package_name'], eco_data['avg_cvss'], eco_data['fix_rate'], eco_data['count'])],
            hovertemplate="%{text}<extra></extra>"
        ))

    fig.add_hline(y=70, line_dash="dash", line_color="#bdc3c7", annotation_text=" 80% Fix Rate Threshold",
                  annotation_position="top left")
    fig.add_vline(x=5.0, line_dash="dash", line_color="#bdc3c7", annotation_text="CVSS 6.0 ",
                  annotation_position="bottom right")

    zone_font = dict(size=14, weight='bold')
    fig.add_annotation(x=3.5, y=85, text="✅ Safe / Stable", showarrow=False, font=dict(**zone_font, color="#27ae60"))
    fig.add_annotation(x=7.5, y=85, text="🟡 High Risk, Actively Fixed", showarrow=False,
                       font=dict(**zone_font, color="#f39c12"))
    fig.add_annotation(x=3.5, y=35, text="🟠 Vulnerable (Low Impact)", showarrow=False,
                       font=dict(**zone_font, color="#e67e22"))
    fig.add_annotation(x=7.5, y=35, text="🔴 DANGER ZONE", showarrow=False, font=dict(**zone_font, color="#c0392b"))

    fig.update_layout(**RISK_MATRIX_LAYOUT)
    fig.update_layout(
        xaxis=dict(title="Average Severity (Higher is more dangerous)", range=[2, 10], gridcolor='#ecf0f1'),
        yaxis=dict(title="Fix Rate % (Higher is better)", range=[-5, 105], gridcolor='#ecf0f1')
    )
    return fig
