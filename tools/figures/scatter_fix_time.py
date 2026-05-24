import pandas as pd
import plotly.graph_objects as go
from tools.config.chart import ECOSYSTEM_COLORS
from tools.metrics import get_weight

def build_fix_time_scatter_fig(df_fix_data: pd.DataFrame) -> go.Figure:
    """Генерирует scatter plot времени исправления против severity."""
    if df_fix_data.empty:
        return go.Figure().update_layout(title="No data available")

    df = df_fix_data.copy()
    
    # Конвертируем даты
    df['intro_date'] = pd.to_datetime(df['intro_date'], errors='coerce', utc=True)
    df['fixed_date'] = pd.to_datetime(df['fixed_date'], errors='coerce', utc=True)
    
    # Считаем время исправления в днях
    df['fix_time'] = (df['fixed_date'] - df['intro_date']).dt.days
    
    # Фильтруем некорректные данные (отрицательное время или NaN)
    df = df[df['fix_time'].notna() & (df['fix_time'] >= 0)]
    
    # Получаем веса severity
    df['severity_weight'] = df['severity'].apply(get_weight)
    
    # Берем по 50 случайных точек на экосистему
    ecosystems = df['package_ecosystem'].unique()
    sampled_df = pd.concat([
        df[df['package_ecosystem'] == eco].sample(n=min(len(df[df['package_ecosystem'] == eco]), 50), random_state=42)
        for eco in ecosystems
    ])

    fig = go.Figure()

    for eco in ecosystems:
        eco_data = sampled_df[sampled_df['package_ecosystem'] == eco]
        if eco_data.empty: continue

        fig.add_trace(go.Scatter(
            x=eco_data['fix_time'],
            y=eco_data['severity_weight'],
            mode='markers',
            name=eco,
            marker=dict(
                color=ECOSYSTEM_COLORS.get(eco, '#333333'),
                size=12,
                opacity=0.7,
                line=dict(width=1, color='white')
            ),
            text=[f"<b>{eco}</b><br>Fix Time: {int(t)} days<br>Severity: {s:.1f}" 
                  for t, s in zip(eco_data['fix_time'], eco_data['severity_weight'])],
            hovertemplate="%{text}<extra></extra>"
        ))

    fig.update_layout(
        title=dict(
            text="Fix Time vs Severity (Sampled 50 points per Ecosystem)",
            font=dict(size=20, family="'Montserrat', sans-serif")
        ),
        xaxis=dict(
            title="Time to Fix (Days)",
            gridcolor='#ecf0f1',
            zerolinecolor='#bdc3c7'
        ),
        yaxis=dict(
            title="Severity Weight (CVSS Scale)",
            gridcolor='#ecf0f1',
            zerolinecolor='#bdc3c7',
            range=[0, 11]
        ),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        margin=dict(l=40, r=40, t=80, b=40)
    )

    return fig
