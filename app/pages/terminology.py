import dash
from dash import html, dcc

dash.register_page(__name__, path='/terminology', name='Terminology')

_SECTION_STYLE = {
    'background': '#161b22',
    'border': '1px solid #30363d',
    'borderRadius': '12px',
    'padding': '28px',
    'marginBottom': '20px',
}

_H2_STYLE = {
    'color': '#e67e22',
    'fontFamily': "'Montserrat', sans-serif",
    'fontSize': '18px',
    'marginTop': '0',
    'marginBottom': '10px',
    'fontWeight': '700'
}

_P_STYLE = {
    'color': '#8b949e',
    'fontSize': '14px',
    'lineHeight': '1.7',
    'marginBottom': '0'
}

_TAG_STYLE = {
    'display': 'inline-block',
    'background': 'rgba(88,166,255,0.1)',
    'border': '1px solid rgba(88,166,255,0.3)',
    'color': '#58a6ff',
    'padding': '2px 10px',
    'borderRadius': '20px',
    'fontSize': '11px',
    'fontWeight': '600',
    'marginRight': '8px',
    'marginBottom': '8px',
    'fontFamily': "'JetBrains Mono', monospace",
    'letterSpacing': '0.5px'
}

_CODE_STYLE = {
    'background': '#21262d',
    'border': '1px solid #30363d',
    'borderRadius': '6px',
    'padding': '12px 16px',
    'fontFamily': "'JetBrains Mono', monospace",
    'fontSize': '13px',
    'color': '#e67e22',
    'display': 'block',
    'marginTop': '10px',
    'lineHeight': '1.8'
}


def term_card(badge, title, body, code=None):
    return html.Div([
        html.Div([
            html.Span(badge, style={**_TAG_STYLE}),
            html.Span(title, style={**_H2_STYLE, 'display': 'inline', 'fontSize': '17px'})
        ], style={'marginBottom': '10px'}),
        html.P(body, style=_P_STYLE),
        html.Code(code, style=_CODE_STYLE) if code else html.Div()
    ], style=_SECTION_STYLE)


layout = html.Div([
    html.H1(
        "Terminology & Guidelines",
        style={
            'textAlign': 'center',
            'fontFamily': "'Montserrat', sans-serif",
            'fontSize': '38px',
            'fontWeight': '700',
            'marginBottom': '8px',
            'color': '#f0f6fc'
        }
    ),
    html.P(
        "Key concepts, metric definitions, and data source guidelines for OSV Insights.",
        style={
            'textAlign': 'center',
            'color': '#8b949e',
            'fontSize': '15px',
            'marginBottom': '40px'
        }
    ),

    html.Div([
        # Left column — concepts
        html.Div([
            # Core concepts
            html.Div([
                html.H2("Base Concepts", style={**_H2_STYLE, 'fontSize': '22px', 'marginBottom': '20px'}),

                term_card("CVE", "Common Vulnerabilities and Exposures",
                    "A standardized identifier for publicly known cybersecurity vulnerabilities. "
                    "Each CVE entry includes an ID (e.g. CVE-2021-44228), a description, and references. "
                    "Managed by MITRE Corporation."),

                term_card("CWE", "Common Weakness Enumeration",
                    "A hierarchical taxonomy of software and hardware weakness types. "
                    "Unlike CVE (specific instances), CWE describes categories of root causes "
                    "(e.g. CWE-79: Cross-site Scripting, CWE-89: SQL Injection). "
                    "OSV Insights uses the MITRE CWE-1000 Research Concepts view — a DAG with 5-6 levels "
                    "from Pillars down to Variants."),

                term_card("CVSS", "Common Vulnerability Scoring System",
                    "A 0–10 numerical score quantifying vulnerability severity. "
                    "CVSS v3.1 considers Attack Vector, Complexity, Privileges Required, User Interaction, "
                    "Scope, and CIA impact. "
                    "OSV Insights uses text labels: LOW (<4), MEDIUM (4–7), HIGH (7–9), CRITICAL (9–10)."),

                term_card("OSV", "Open Source Vulnerabilities Database",
                    "Google's open-source vulnerability database and schema standard. "
                    "Aggregates data from NVD, GitHub Advisory, PyPI Advisory and more into a unified JSON format. "
                    "This project pulls from the OSV API and stores results in PostgreSQL."),

                term_card("EPSS", "Exploit Prediction Scoring System",
                    "A probabilistic score (0–1) estimating the likelihood that a vulnerability "
                    "will be exploited in the wild within the next 30 days. "
                    "Complements CVSS — a LOW-CVSS vulnerability with high EPSS is still dangerous."),
            ]),

            # Metrics
            html.Div([
                html.H2("Metric Definitions", style={**_H2_STYLE, 'fontSize': '22px', 'marginBottom': '20px', 'marginTop': '32px'}),

                term_card("M1", "Integral Risk Score",
                    "Composite severity metric with an aging penalty for long-standing unfixed vulnerabilities.",
                    code="score = Σ(cvss_weight × unfixed_branches × aging_coeff) / total_branches\n"
                         "aging_coeff: <6mo→0.5  6-12mo→1.0  1-2yr→2.5  >2yr→5.0"),

                term_card("M2", "Staleness Index",
                    "Percentage of unfixed vulnerabilities older than 2 years. "
                    "High staleness means the ecosystem accumulates long-lived unresolved issues.",
                    code="staleness = (unfixed_vulns_older_2yr / total_vulns) × 100%"),

                term_card("M3", "Mean Time to Repair (MTTR)",
                    "Average age in days of currently unfixed vulnerabilities from their introduction date.",
                    code="mttr = mean(today - intro_date)  for all unfixed vulnerabilities"),

                term_card("M4", "High/Critical Severity Ratio",
                    "Share of unfixed vulnerabilities with CVSS ≥ 7.0 (HIGH or CRITICAL).",
                    code="ratio = (unfixed_HIGH_or_CRITICAL / total_vulns) × 100%"),

                term_card("M5", "Defect Density",
                    "Average number of vulnerabilities per unique package. "
                    "High density indicates systemic quality issues within an ecosystem.",
                    code="density = total_vulnerabilities / unique_packages"),

                term_card("M6", "Risk Concentration (Pareto)",
                    "Percentage of all vulnerabilities concentrated in the top-5 most affected packages. "
                    "High concentration (>70%) means fixing 5 packages dramatically improves security.",
                    code="concentration = top5_package_vuln_count / total_vulns × 100%"),

                term_card("M7", "Open-to-Close Ratio",
                    "Ratio of unfixed to fixed vulnerabilities. "
                    "Values >1 indicate growing security debt; <1 means the ecosystem is catching up.",
                    code="ratio = unfixed_count / fixed_count"),
            ]),

        ], style={'flex': '1', 'minWidth': '0'}),

        # Right column — data sources
        html.Div([
            html.Div([
                html.H2("CWE Hierarchy", style={**_H2_STYLE, 'fontSize': '18px'}),
                html.P("The CWE-1000 Research Concepts view is a Directed Acyclic Graph (DAG) with 5-6 levels:", style=_P_STYLE),
                html.Div([
                    html.Div("Pillar → Class → Base → Variant → Compound", style={**_CODE_STYLE}),
                ]),
                html.P("OSV Insights maps every CVE's CWE to one of 10 root Pillars for aggregation in the Radar and Heatmap views.", style={**_P_STYLE, 'marginTop': '10px'}),
                html.Div([
                    html.Span(f"CWE-{c}", style=_TAG_STYLE)
                    for c in ['284', '435', '664', '682', '691', '693', '697', '703', '707', '710']
                ], style={'marginTop': '12px'})
            ], style=_SECTION_STYLE),

            html.Div([
                html.H2("Normalization Formula", style={**_H2_STYLE, 'fontSize': '18px'}),
                html.P("Radar chart metrics are normalized using logarithmic scaling to prevent extreme outliers from collapsing all other values:", style=_P_STYLE),
                html.Code("normalized = 100 × log₂(1 + value / max_value)", style=_CODE_STYLE),
                html.P("This compression preserves relative differences while keeping all values in [0, 100].", style={**_P_STYLE, 'marginTop': '10px'})
            ], style=_SECTION_STYLE),

            html.Div([
                html.H2("Data Source", style={**_H2_STYLE, 'fontSize': '18px'}),
                html.P("Data sourced from Google OSV Database via REST API. Stored in PostgreSQL with 3 tables:", style=_P_STYLE),
                html.Code(
                    "vulnerabilities  — CVE metadata, CVSS, CWE\n"
                    "packages         — name, ecosystem\n"
                    "affections       — JSONB ranges (versions + events)",
                    style=_CODE_STYLE
                ),
                html.P("Connection via SSH tunnel to VPS. All queries run against a cached global DataFrame loaded at app startup.", style={**_P_STYLE, 'marginTop': '10px'})
            ], style=_SECTION_STYLE),

            html.Div([
                html.H2("Ecosystems", style={**_H2_STYLE, 'fontSize': '18px'}),
                html.Div([
                    html.Div([
                        html.Span("PyPI", style={**_TAG_STYLE, 'background': 'rgba(88,166,255,0.1)', 'borderColor': 'rgba(88,166,255,0.3)', 'color': '#58a6ff'}),
                        html.Span("Python packages from pypi.org", style={'color': '#8b949e', 'fontSize': '13px'})
                    ], style={'marginBottom': '8px'}),
                    html.Div([
                        html.Span("npm", style={**_TAG_STYLE, 'background': 'rgba(248,81,73,0.1)', 'borderColor': 'rgba(248,81,73,0.3)', 'color': '#f85149'}),
                        html.Span("Node.js packages from npmjs.com", style={'color': '#8b949e', 'fontSize': '13px'})
                    ], style={'marginBottom': '8px'}),
                    html.Div([
                        html.Span("Go", style={**_TAG_STYLE, 'background': 'rgba(63,185,80,0.1)', 'borderColor': 'rgba(63,185,80,0.3)', 'color': '#3fb950'}),
                        html.Span("Go modules from pkg.go.dev", style={'color': '#8b949e', 'fontSize': '13px'})
                    ], style={'marginBottom': '8px'}),
                    html.Div([
                        html.Span("Maven", style={**_TAG_STYLE, 'background': 'rgba(210,168,255,0.1)', 'borderColor': 'rgba(210,168,255,0.3)', 'color': '#d2a8ff'}),
                        html.Span("Java packages from search.maven.org", style={'color': '#8b949e', 'fontSize': '13px'})
                    ]),
                ])
            ], style=_SECTION_STYLE),

        ], style={'width': '360px', 'flexShrink': '0', 'marginLeft': '24px'}),

    ], style={
        'display': 'flex',
        'alignItems': 'flex-start',
        'gap': '0',
        'maxWidth': '1200px',
        'margin': '0 auto'
    })
])
