import json
import csv
from pathlib import Path

def extract_versions(affected_list):
    fixed_parts = []
    last_affected_parts = []
    for aff in affected_list:
        pkg_name = aff.get("package", {}).get("name", "unknown")
        ranges = aff.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            for ev in events:
                if "fixed" in ev:
                    fixed_parts.append(f"{pkg_name}: {ev['fixed']}")
                if "last_affected" in ev:
                    last_affected_parts.append(f"{pkg_name}: {ev['last_affected']}")
        if not ranges:
            versions = aff.get("versions", [])
            if versions:
                last_affected_parts.append(f"{pkg_name}: {versions[-1]}")
    return "; ".join(fixed_parts) if fixed_parts else "", "; ".join(last_affected_parts) if last_affected_parts else ""


def fetch_osv_data_filtered(ecosystem, data_dir="data"):
    input_path = Path(data_dir) / ecosystem
    results = []
    for json_file in input_path.glob("*.json"):
        with open(json_file, encoding="utf-8") as f:
            data = json.load(f)
        withdrawn = data.get("withdrawn", "")
        if withdrawn:
            continue
        is_false_positive = False
        if data.get("false_positive") is True:
            is_false_positive = True
        db_specific = data.get("database_specific", {})

        if isinstance(db_specific, dict) and db_specific.get("false_positive") is True:
            is_false_positive = True

        if is_false_positive:
            continue

        vuln_id = data.get("id", "")
        title = data.get("summary", "")
        description = data.get("details", "")
        aliases = ", ".join(data.get("aliases", []))
        severity_list = data.get("severity", [])
        severity_str = ""

        if severity_list:
            sev = severity_list[0]
            severity_str = f"{sev.get('type', '')} {sev.get('score', '')}".strip()

        published = data.get("published", "")

        affected = data.get("affected", [])
        fixed, last_affected = extract_versions(affected)

        results.append({
            "id": vuln_id,
            "title": title,
            "description": description,
            "aliases": aliases,
            "severity": severity_str,
            "published": published,
            "fixed": fixed,
            "last_affected": last_affected,
            "database_specific": db_specific
        })
    return results


def save_filtered_csv(ecosystem, data, output_dir="output"):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    csv_file = output_path / f"{ecosystem}_filtered.csv"

    fieldnames = ["id", "title", "description", "aliases", "severity",
                  "published", "fixed", "last_affected"]

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


def parse_single_vulnerability(data: dict):
    if data.get("withdrawn", "") or data.get("false_positive") is True:
        return None
    db_specific = data.get("database_specific", {})
    if isinstance(db_specific, dict) and db_specific.get("false_positive") is True:
        return None
    vuln_id = data.get("id", "")
    title = data.get("summary", "")
    description = data.get("details", "")
    aliases = ", ".join(data.get("aliases", []))

    severity_str = ""
    severity_list = data.get("severity", [])
    if severity_list:
        sev = severity_list[0]
        severity_str = f"{sev.get('type', '')} {sev.get('score', '')}".strip()

    published = data.get("published", "")
    affected = data.get("affected", [])
    fixed, last_affected = extract_versions(affected)

    return {
        "id": vuln_id,
        "title": title,
        "description": description,
        "aliases": aliases,
        "severity": severity_str,
        "published": published,
        "fixed": fixed,
        "last_affected": last_affected,
        "database_specific": db_specific
    }
