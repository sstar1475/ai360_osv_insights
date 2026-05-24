from dash import dcc, html, callback, Input, Output
from tools.figures.scatter_fix_time import build_fix_time_scatter_fig
from app.app import df_fix_time

def create_fix_time_scatter_chart() -> html.Div:
    return html.Div([
        html.H3(
            "Fix Time vs Severity Scatter Analysis",
            id='fix-time-scatter-btn',
            className='collapsible-header',
            style={'color': '#e67e22', 'marginTop': '0', 'fontFamily': "'Montserrat', sans-serif"}
        ),

        html.Div([
            html.P(
                "Each point represents an individual vulnerability. The X-axis shows the time taken to fix (from introduction to fix), and the Y-axis shows its severity weight. Data is sampled to 50 points per ecosystem for clarity.",
                style={'color': '#7f8c8d', 'fontSize': '16px', 'marginBottom': '25px'}),

            dcc.Graph(
                id='fix-time-scatter-graph',
                figure=build_fix_time_scatter_fig(df_fix_time),
                config={'displayModeBar': False}
            )
        ], id='fix-time-scatter-content', className='collapsible-content')
    ], style={'width': '100%', 'display': 'flex', 'flexDirection': 'column', 'marginBottom': '30px'})

@callback(
    Output('fix-time-scatter-content', 'className'),
    Output('fix-time-scatter-btn', 'className'),
    Input('fix-time-scatter-btn', 'n_clicks'),
    prevent_initial_call=True
)
def toggle_fix_time_collapse(n_clicks):
    # Упрощенная логика переключения для демонстрации
    if n_clicks and n_clicks % 2 == 1:
        return "collapsible-content collapsed", "collapsible-header"
    return "collapsible-content", "collapsible-header active"
