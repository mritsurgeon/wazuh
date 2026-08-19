import csv
import sys
from lxml import etree

GENERIC_ID_RANGE = range(131000, 132000)
FIELD_ID_RANGE = range(132000, 133000)


def check_well_formed(xml_paths: list[str]) -> list[str]:
    errors = []
    for path in xml_paths:
        try:
            etree.parse(path)
        except etree.XMLSyntaxError as e:
            errors.append(f"{path}: not well-formed XML: {e}")
    return errors


def _all_rule_ids(path: str) -> list[str]:
    tree = etree.parse(path)
    return [r.get("id") for r in tree.findall(".//rule")]


def check_unique_ids(xml_paths: list[str]) -> list[str]:
    seen = {}
    errors = []
    for path in xml_paths:
        for rule_id in _all_rule_ids(path):
            if rule_id in seen:
                errors.append(f"duplicate rule id {rule_id} in {path} and {seen[rule_id]}")
            else:
                seen[rule_id] = path
    return errors


def check_id_ranges(generic_path: str, field_path: str) -> list[str]:
    errors = []
    for rule_id in _all_rule_ids(generic_path):
        if int(rule_id) not in GENERIC_ID_RANGE:
            errors.append(f"generic rule id {rule_id} outside 131000-131999")
    for rule_id in _all_rule_ids(field_path):
        if int(rule_id) not in FIELD_ID_RANGE:
            errors.append(f"field rule id {rule_id} outside 132000-132999")
    return errors


def check_event_coverage(generic_path: str, csv_path: str) -> list[str]:
    tree = etree.parse(generic_path)
    covered = {
        el.text for el in tree.findall(".//rule/field[@name='EventID']")
    }
    with open(csv_path, newline="", encoding="utf-8") as f:
        expected = {row["event_id"] for row in csv.DictReader(f)}
    missing = expected - covered
    return [f"EventID {eid} has no generic rule" for eid in sorted(missing)]


def check_if_sid_resolves(field_path: str, generic_path: str) -> list[str]:
    # Deliberately generic-only, not a union with field_path's own IDs: Task 8's
    # design is one field rule chained directly to its generic counterpart, never
    # field-to-field. Accepting a field-to-field if_sid here would hide a real
    # authoring mistake during Task 8.
    generic_ids = set(_all_rule_ids(generic_path))
    tree = etree.parse(field_path)
    errors = []
    for el in tree.findall(".//rule/if_sid"):
        if el.text not in generic_ids:
            errors.append(f"if_sid {el.text} does not resolve to any known generic rule id")
    return errors


def run_all(generic_path: str, field_path: str, csv_path: str) -> list[str]:
    errors = []
    errors += check_well_formed([generic_path, field_path])
    if errors:
        return errors  # can't safely run the rest against broken XML
    errors += check_unique_ids([generic_path, field_path])
    errors += check_id_ranges(generic_path, field_path)
    errors += check_event_coverage(generic_path, csv_path)
    errors += check_if_sid_resolves(field_path, generic_path)
    return errors


if __name__ == "__main__":
    generic_path, field_path, csv_path = sys.argv[1], sys.argv[2], sys.argv[3]
    errors = run_all(generic_path, field_path, csv_path)
    for e in errors:
        print(e)
    sys.exit(1 if errors else 0)
