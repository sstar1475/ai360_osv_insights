import xml.etree.ElementTree as ET
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
XML_path = BASE_DIR / 'cwec_v4.20.xml'

def get_highest_parents_for_view(xml_path, target_view="1000"):
    ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}

    tree = ET.parse(xml_path)
    root = tree.getroot()

    parents_map = {}
    kids_map = {}
    for weakness in root.findall('.//cwe:Weaknesses/cwe:Weakness', ns):
        w_id = weakness.attrib.get('ID')
        for related in weakness.findall('.//cwe:Related_Weaknesses/cwe:Related_Weakness', ns):
            if related.attrib.get('View_ID') == target_view and related.attrib.get('Nature') == 'ChildOf':
                parent_id = related.attrib.get('CWE_ID')
                kids_map.setdefault(parent_id, set()).add(w_id)

                parents_map.setdefault(w_id, set()).add(parent_id)
    containers = root.findall('.//cwe:Categories/cwe:Category', ns) + root.findall('.//cwe:Views/cwe:View', ns)
    for container in containers:
        parent_id = container.attrib.get('ID')
        for member in container.findall('.//cwe:Relationships/cwe:Has_Member', ns):
            if member.attrib.get('View_ID') == target_view:
                child_id = member.attrib.get('CWE_ID')
                kids_map.setdefault(parent_id, set()).add(child_id)
                parents_map.setdefault(child_id, set()).add(parent_id)
    return parents_map, kids_map

Parents, Kids = get_highest_parents_for_view(XML_path, target_view="1000")
Kids['1000'] = {"284", "435", "664", "682", "691", "693", "697", "703", "707", "710"}

def get_all_ancestors(cwe_id: str, parents: dict[str, list[str]], height: int = 0) -> list[tuple[str, int]]:
    ans = []
    if cwe_id not in parents:
        return ans
    for parent_id in parents[cwe_id]:
        ans.append((parent_id, height + 1))
    for parent_id in parents[cwe_id]:
        if parent_id not in parents:
            continue
        ans += get_all_ancestors(parent_id, parents, height + 1)
    return ans
def get_all_descendants(cwe_id: str, kids: dict[str, list[str]], height: int = 0) -> list[tuple[str, int]]:
    ans = []
    if cwe_id not in kids:
        return ans
    for kid_id in kids[cwe_id]:
        ans.append((kid_id, height + 1))
    for kid_id in kids[cwe_id]:
        if kid_id not in kids:
            continue
        ans += get_all_descendants(kid_id, kids, height + 1)
    return ans
