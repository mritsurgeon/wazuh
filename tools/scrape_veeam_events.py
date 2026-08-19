"""Scraper for Veeam Backup & Replication 13.1's official event ID table.

The source page (https://helpcenter.veeam.com/docs/vbr/events/event_id_list.html?ver=13)
is server-rendered HTML with a single flat table -- there are no per-category
header rows and no separate "severity" or "message details" columns. Those
fields are kept in the output dict for interface compatibility with later
tasks (CSV consumers, decoder generator) but are always empty strings, since
the source page does not provide that data.

Real table structure found on the live page (verified via curl):
    <table class="Blue_Table"> with 332 <tr> total (1 header + 331 data rows),
    each row exactly 6 <td>/<th> cells in this order:
        0: Event ID
        1: Event Name
        2: MITRE ATT&CK Tactic
        3: MITRE ATT&CK Technique
        4: NIST 800-53r5
        5: Veeam Products and Components

    "Blank" values are not empty <td> cells -- they are the literal text
    "N/A". That literal is normalized to "" here to satisfy the
    empty-string-not-None contract required by downstream consumers.

    Column 5 ("Veeam Products and Components") is not part of the required
    output schema and is intentionally discarded.
"""

import csv
import sys

import requests
from bs4 import BeautifulSoup

FIELDS = [
    "event_id", "category", "message_summary", "message_details",
    "severity", "mitre_tactic", "mitre_technique", "nist_800_53r5",
]

SOURCE_URL = "https://helpcenter.veeam.com/docs/vbr/events/event_id_list.html?ver=13"


def fetch_page(url: str) -> str:
    """Fetch a URL's HTML body as text."""
    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=30)
    response.raise_for_status()
    return response.text


def _clean(value: str) -> str:
    """Normalize a cell's text: strip whitespace, treat the source's "N/A"
    placeholder as blank so downstream consumers see a consistent empty
    string rather than the literal text."""
    text = value.strip()
    return "" if text == "N/A" else text


def parse_events_table(html: str) -> list[dict]:
    """Parse the VBR 13.1 event ID table into a list of event dicts.

    The live table has no category-header rows and no severity/message-details
    columns, so those fields are always "" -- they exist only so the output
    schema matches what later tasks (CSV writer, decoder generator) expect.
    """
    soup = BeautifulSoup(html, "lxml")
    table = soup.find("table")
    if table is None:
        return []

    events = []
    rows = table.find_all("tr")
    for row in rows:
        cells = row.find_all(["td", "th"])
        if not cells:
            continue
        # Skip the header row (its cells are <th>, not <td>).
        if row.find("th") is not None:
            continue

        values = [_clean(c.get_text(" ", strip=True)) for c in cells]
        event_id = values[0] if len(values) > 0 else ""
        if not event_id or not event_id[0].isdigit():
            continue

        events.append({
            "event_id": event_id,
            "category": "",
            "message_summary": values[1] if len(values) > 1 else "",
            "message_details": "",
            "severity": "",
            "mitre_tactic": values[2] if len(values) > 2 else "",
            "mitre_technique": values[3] if len(values) > 3 else "",
            "nist_800_53r5": values[4] if len(values) > 4 else "",
        })
    return events


def write_csv(events: list[dict], path: str) -> None:
    """Write parsed events to a CSV file at `path` using the FIELDS schema."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(events)


if __name__ == "__main__":
    output_path = sys.argv[1]
    page_html = fetch_page(SOURCE_URL)
    parsed_events = parse_events_table(page_html)
    write_csv(parsed_events, output_path)
    print(f"Wrote {len(parsed_events)} events to {output_path}")
