from tools.metrics import (
    calc_integral_severity, calc_staleness_index,
    calc_avg_unfixed_life, calc_high_severity_ratio,
    calc_defect_density
)

ALL_METRICS = {
    'metric_1': {
        'func': calc_integral_severity,
        'label': 'Integral Risk Score',
        'color': '#1f77b4'
    },
    'metric_2': {
        'func': calc_staleness_index,
        'label': 'Ecosystem Dependency Staleness Index (>2 years)',
        'color': '#ff7f0e'
    },
    'metric_3': {
        'func': calc_avg_unfixed_life,
        'label': 'Mean Time to Repair (MTTR in days)',
        'color': '#2ca02c'
    },
    'metric_4': {
        'func': calc_high_severity_ratio,
        'label': 'Ratio of High/Critical Severity (>= 7.0)',
        'color': '#d62728'
    },
    'metric_5': {
        'func': calc_defect_density,
        'label': 'Vulnerability Defect Density',
        'color': '#9467bd'
    }
}
