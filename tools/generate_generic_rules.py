"""Generate one generic Wazuh rule per Veeam event ID from a scraped events CSV.

Consumes rows shaped like tools/scrape_veeam_events.py's parse_events_table
output (dicts with event_id, category, message_summary, severity, ...) and
produces a Wazuh rule XML file with one <rule> per event, matching the
<decoded_as>Veeam MP 13.1</decoded_as> / <field name="EventID"> convention
used by the decoder that pairs with these rules. The EventID field is
anchored (^{event_id}$) so it never substring-matches a longer numeric
EventID (e.g. "200" must not match "42200").
"""

import csv
import sys
from xml.sax.saxutils import escape

# Wazuh level convention used by the rest of this repo: info -> 3,
# warning -> 6, error -> 8. (Unrecognized/potential-IOC-flavored strings
# would map to 12, but none of the scraped severities need that bucket --
# this generic generator only ever sees info/warning/error combinations.)
SEVERITY_LEVELS = {
    "error": 8,
    "warning": 6,
    "info": 3,
}


def severity_to_level(severity: str) -> int:
    """Map a raw severity string to a Wazuh level.

    Real scraped data is messier than a clean "Info"/"Warning"/"Error"
    value: some events report multiple severities depending on outcome
    (e.g. "Info, Warning, Error"), some rows are empty (event had no live
    detail page to scrape), and at least one page has a typo ("Waring").

    Matching is case-insensitive substring matching against the whole
    string, and when multiple levels are present we take the highest
    (worst-case) one: error > warning > info. This means a typo like
    "Waring" alone won't match "warning" (it's a genuine typo, not
    special-cased), but "Info, Waring, Error" still resolves to 8 because
    "error" is present and matched via substring.

    Empty or unrecognized strings default to 3 (informational), the
    safest default absent better data.
    """
    normalized = severity.strip().lower()
    for keyword in ("error", "warning", "info"):
        if keyword in normalized:
            return SEVERITY_LEVELS[keyword]
    return 3


def build_rule_xml(event: dict, rule_id: int) -> str:
    level = severity_to_level(event["severity"])
    summary = escape(event["message_summary"] or event["event_id"])
    return (
        f'  <rule id="{rule_id}" level="{level}">\n'
        f'    <decoded_as>Veeam MP 13.1</decoded_as>\n'
        f'    <description>{summary}: $(Description)</description>\n'
        f'    <field name="EventID">^{event["event_id"]}$</field>\n'
        f'  </rule>\n'
    )


def generate_rules_file(csv_path: str, output_path: str, start_id: int = 131000) -> None:
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    body = "".join(
        build_rule_xml(row, start_id + i) for i, row in enumerate(rows)
    )
    xml = (
        "<!-- Veeam Backup & Replication 13.1 -->\n"
        "<!-- Generated from v13.1/veeam_events_13.1.csv by tools/generate_generic_rules.py -->\n"
        '<group name="Veeam_Backup_Replication_13.1">\n'
        f"{body}"
        "</group>\n"
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml)


if __name__ == "__main__":
    generate_rules_file(sys.argv[1], sys.argv[2])
