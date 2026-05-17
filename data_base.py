import json
import csv
from pathlib import Path
from osv_tools.parsing import parse_single_vulnerability



all_dir = Path(__file__).parent / "all"
processed = []
for json_file in all_dir.glob("*.json"): #glob("GHSA*.json") чтобы только GHSA уязвимости рассматривать
    try:
        with open(json_file, encoding="utf-8") as f:
            data = json.load(f)
        entry = parse_single_vulnerability(data)
        if entry is not None:
            processed.append(entry)
    except Exception as e:
        pass

output_path = Path(__file__).parent / "vulnerabilities_filtered.csv"
fieldnames = ["id", "title", "description", "aliases", "severity",
              "published", "fixed", "last_affected", "database_specific"]
with open(output_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(processed)

print(f"Обработано {len(processed)} записей")
print(f"Результат сохранён в {output_path}")

