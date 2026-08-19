"""Scraper for Veeam Backup & Replication 13.1's official event ID table.

The source summary page (https://helpcenter.veeam.com/docs/vbr/events/event_id_list.html?ver=13)
is server-rendered HTML with a single flat table -- there are no per-category
header rows and no separate "severity" or "message details" columns. Those
fields (category, message_details, severity, parameters) come instead from
each event's own detail page (https://helpcenter.veeam.com/docs/vbr/events/event_<id>.html),
fetched and merged in via `fetch_event_detail` / `enrich_events_with_details`.

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
import time

import requests
from bs4 import BeautifulSoup

FIELDS = [
    "event_id", "category", "message_summary", "message_details",
    "severity", "mitre_tactic", "mitre_technique", "nist_800_53r5",
    "parameters",
]

SOURCE_URL = "https://helpcenter.veeam.com/docs/vbr/events/event_id_list.html?ver=13"
DETAIL_URL_TEMPLATE = "https://helpcenter.veeam.com/docs/vbr/events/event_{event_id}.html"


def fetch_page(url: str) -> str:
    """Fetch a URL's HTML body as text.

    Decodes the response body as UTF-8 explicitly rather than trusting
    `requests`' `.text` auto-detection. Veeam's helpcenter pages declare
    `<meta charset="utf-8">` but the HTTP `Content-Type` header omits a
    charset parameter -- when that happens `requests` falls back to
    ISO-8859-1 per the HTTP spec's historical default, which silently
    mangles multi-byte UTF-8 sequences (e.g. a UTF-8 non-breaking space,
    bytes 0xC2 0xA0, gets decoded as the two separate Latin-1 characters
    "Â\xa0" -- the classic "Â" mojibake). Decoding `response.content`
    (raw bytes) as UTF-8 ourselves sidesteps that fallback entirely.
    """
    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=30)
    response.raise_for_status()
    return response.content.decode("utf-8")


def _clean(value: str) -> str:
    """Normalize a cell's text: strip whitespace, treat the source's "N/A"
    placeholder as blank so downstream consumers see a consistent empty
    string rather than the literal text."""
    text = value.strip()
    return "" if text == "N/A" else text


def parse_events_table(html: str) -> list[dict]:
    """Parse the VBR 13.1 event ID table into a list of event dicts.

    The live table has no category-header rows and no severity/message-details
    columns, so those fields (and `parameters`) are always "" here -- callers
    should run the result through `enrich_events_with_details` to populate
    them from each event's detail page.
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
            "parameters": "",
        })
    return events


def fetch_event_detail(event_id: str) -> dict:
    """Fetch and parse a single event's detail page.

    Detail pages (event_<id>.html) carry data the summary table lacks:
    category (derived from the page's breadcrumb meta tag), the full
    message-details text, severity, and a Parameters table describing each
    named placeholder that can appear in the message.

    Returns a dict: {"category": str, "message_details": str,
    "severity": str, "parameters": list[{"name": str, "example": str}]}.
    """
    url = DETAIL_URL_TEMPLATE.format(event_id=event_id)
    html = fetch_page(url)
    soup = BeautifulSoup(html, "lxml")

    # Category: the breadcrumb meta tag looks like
    # "Event Reference > Backup > Jobs > Backup Job Started" -- the first
    # segment is always the site-wide "Event Reference" root and the last
    # segment duplicates the event's own name, so the category is
    # everything in between.
    category = ""
    breadcrumb_tag = soup.find("meta", attrs={"name": "breadcrumb"})
    if breadcrumb_tag is not None:
        content = breadcrumb_tag.get("content", "")
        segments = [s.strip() for s in content.split(">") if s.strip()]
        if len(segments) > 2:
            category = " > ".join(segments[1:-1])
        elif len(segments) == 2:
            # Only "Event Reference > X" -- no separate final "event name"
            # segment to drop, so the whole remainder is the category.
            category = segments[1]

    # General Information: "Event message details" and "Severity" are
    # plain paragraphs identified by their leading <span class="T_Controls">
    # label text, not by table cells.
    message_details = ""
    severity = ""
    for p in soup.find_all("p"):
        label = p.find("span", class_="T_Controls")
        if label is None:
            continue
        label_text = label.get_text(strip=True)
        # Full paragraph text minus the label, minus the leading ": ".
        # get_text(" ", ...) can insert a space between the label span and
        # the colon that follows it, so strip whitespace before stripping
        # the colon itself.
        full_text = p.get_text(" ", strip=True)
        value = full_text[len(label_text):].strip().lstrip(":").strip()
        if label_text == "Event message details":
            message_details = _clean(value)
        elif label_text == "Severity":
            severity = _clean(value)

    # Parameters: the <table class="Blue_Table"> immediately following the
    # "Parameters" <p class="Subheading"> heading. Not every event page has
    # one, so absence is normal, not an error.
    parameters = []
    params_heading = None
    for p in soup.find_all("p", class_="Subheading"):
        if p.get_text(strip=True) == "Parameters":
            params_heading = p
            break
    if params_heading is not None:
        params_table = params_heading.find_next("table", class_="Blue_Table")
        if params_table is not None:
            rows = params_table.find_all("tr")
            for row in rows:
                if row.find("th") is not None:
                    continue
                cells = row.find_all("td")
                if len(cells) < 3:
                    continue
                name = _clean(cells[0].get_text(" ", strip=True))
                example = _clean(cells[2].get_text(" ", strip=True))
                parameters.append({"name": name, "example": example})

    return {
        "category": category,
        "message_details": message_details,
        "severity": severity,
        "parameters": parameters,
    }


def _serialize_parameters(parameters: list[dict]) -> str:
    """Serialize a list of {"name", "example"} dicts into the CSV-friendly
    `parameters` column value.

    The site's own "Example" cell text already embeds the parameter name
    (e.g. `JobSessionID="c0d93abe-..."`, not just the bare value), so the
    column is just the Example values joined with ";" -- prefixing each
    with its own name too would duplicate it (`JobSessionID=JobSessionID=...`).
    """
    return ";".join(p["example"] for p in parameters)


def enrich_events_with_details(events: list[dict], delay_seconds: float = 0.5) -> list[dict]:
    """Fetch each event's detail page and merge category/message_details/
    severity/parameters into the table-scraped event dicts.

    Sleeps `delay_seconds` between requests as a politeness rate limit --
    this hits the live site once per event (331 events as of VBR 13.1), so
    the delay is not optional: removing it would hammer Veeam's help
    center with rapid-fire requests.

    A handful of event IDs listed in the summary table have no standalone
    detail page (404) -- those are skipped with a warning on stderr rather
    than aborting the whole run, and keep whatever (empty) values they had
    from the table scrape.
    """
    enriched = []
    for event in events:
        merged = dict(event)
        try:
            detail = fetch_event_detail(event["event_id"])
        except requests.exceptions.RequestException as exc:
            print(
                f"Warning: could not fetch detail page for event "
                f"{event['event_id']}: {exc}",
                file=sys.stderr,
            )
        else:
            merged["category"] = detail["category"]
            merged["message_details"] = detail["message_details"]
            merged["severity"] = detail["severity"]
            merged["parameters"] = _serialize_parameters(detail["parameters"])
        enriched.append(merged)
        time.sleep(delay_seconds)
    return enriched


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
    enriched_events = enrich_events_with_details(parsed_events)
    write_csv(enriched_events, output_path)
    print(f"Wrote {len(enriched_events)} events to {output_path}")
