from pathlib import Path
from unittest.mock import patch

from tools.scrape_veeam_events import (
    FIELDS,
    enrich_events_with_details,
    fetch_event_detail,
    parse_events_table,
    write_csv,
)

FIXTURE = Path(__file__).parent / "fixtures" / "veeam_events_13_sample.html"
DETAIL_FIXTURE = Path(__file__).parent / "fixtures" / "veeam_event_detail_110_sample.html"


def test_parse_events_table_returns_expected_row_count():
    html = FIXTURE.read_text()
    events = parse_events_table(html)
    assert len(events) == 5


def test_parse_events_table_extracts_known_row():
    html = FIXTURE.read_text()
    events = parse_events_table(html)
    ids = {e["event_id"] for e in events}
    assert "115" in ids


def test_parse_events_table_extracts_full_mitre_nist_row():
    html = FIXTURE.read_text()
    events = parse_events_table(html)
    by_id = {e["event_id"]: e for e in events}
    row = by_id["115"]
    assert row["message_summary"] == "Tape Erase Job Started"
    assert row["mitre_tactic"] == "TA0040"
    assert row["mitre_technique"] == "T1485, T1490"
    assert row["nist_800_53r5"] == (
        "AC-2, AC-3, AC-6, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7"
    )


def test_parse_events_table_na_cells_become_empty_string():
    html = FIXTURE.read_text()
    events = parse_events_table(html)
    by_id = {e["event_id"]: e for e in events}
    row = by_id["110"]
    assert row["mitre_tactic"] == ""
    assert row["mitre_technique"] == ""
    assert row["nist_800_53r5"] == ""


def test_parse_events_table_blank_cells_become_empty_string_not_none():
    html = FIXTURE.read_text()
    events = parse_events_table(html)
    for e in events:
        for key, value in e.items():
            assert value is not None, f"{key} was None instead of ''"


def test_parse_events_table_all_fields_present():
    html = FIXTURE.read_text()
    events = parse_events_table(html)
    expected_keys = {
        "event_id",
        "category",
        "message_summary",
        "message_details",
        "severity",
        "mitre_tactic",
        "mitre_technique",
        "nist_800_53r5",
        "parameters",
    }
    for e in events:
        assert set(e.keys()) == expected_keys


def test_fetch_event_detail_parses_category_from_breadcrumb():
    html = DETAIL_FIXTURE.read_text()
    with patch("tools.scrape_veeam_events.fetch_page", return_value=html):
        detail = fetch_event_detail("110")
    assert detail["category"] == "Backup > Jobs"


def test_fetch_event_detail_parses_message_details_and_severity():
    html = DETAIL_FIXTURE.read_text()
    with patch("tools.scrape_veeam_events.fetch_page", return_value=html):
        detail = fetch_event_detail("110")
    assert detail["message_details"] == (
        "Backup job <JobName> has been started by user <UserName>"
    )
    assert detail["severity"] == "Info"


def test_fetch_event_detail_parses_parameters_table_in_order():
    html = DETAIL_FIXTURE.read_text()
    with patch("tools.scrape_veeam_events.fetch_page", return_value=html):
        detail = fetch_event_detail("110")
    assert detail["parameters"] == [
        {"name": "JobSessionID", "example": 'JobSessionID="c0d93abe-3adf-4397-b762-351b73acf7e1"'},
        {"name": "JobID", "example": 'JobID="c4415b30-de82-4403-8816-ea66636356e8"'},
        {"name": "JobType", "example": 'JobType="0"'},
        {"name": "Platform", "example": 'Platform="0"'},
    ]


def test_fetch_event_detail_handles_missing_parameters_section():
    html = "<html><head><meta name=\"breadcrumb\" content=\"Event Reference &gt; Backup &gt; Widget\"></head><body></body></html>"
    with patch("tools.scrape_veeam_events.fetch_page", return_value=html):
        detail = fetch_event_detail("999")
    assert detail["parameters"] == []
    assert detail["category"] == "Backup"


def test_enrich_events_with_details_merges_and_rate_limits(monkeypatch):
    events = [
        {"event_id": "110", "category": "", "message_summary": "Backup Job Started",
         "message_details": "", "severity": "", "mitre_tactic": "", "mitre_technique": "",
         "nist_800_53r5": "", "parameters": ""},
        {"event_id": "114", "category": "", "message_summary": "File to Tape Job Started",
         "message_details": "", "severity": "", "mitre_tactic": "", "mitre_technique": "",
         "nist_800_53r5": "", "parameters": ""},
    ]

    fake_details = {
        "110": {"category": "Backup > Jobs", "message_details": "msg 110", "severity": "Info",
                "parameters": [{"name": "A", "example": "A_val"}]},
        "114": {"category": "Backup > Jobs", "message_details": "msg 114", "severity": "Warning",
                "parameters": []},
    }

    sleep_calls = []

    with patch(
        "tools.scrape_veeam_events.fetch_event_detail",
        side_effect=lambda event_id: fake_details[event_id],
    ), patch("tools.scrape_veeam_events.time.sleep", side_effect=sleep_calls.append):
        enriched = enrich_events_with_details(events, delay_seconds=0.5)

    by_id = {e["event_id"]: e for e in enriched}
    assert by_id["110"]["category"] == "Backup > Jobs"
    assert by_id["110"]["message_details"] == "msg 110"
    assert by_id["110"]["severity"] == "Info"
    assert by_id["110"]["parameters"] == "A_val"
    assert by_id["114"]["parameters"] == ""
    assert sleep_calls == [0.5, 0.5]


def test_write_csv_includes_parameters_column(tmp_path):
    events = [{
        "event_id": "110",
        "category": "Backup > Jobs",
        "message_summary": "Backup Job Started",
        "message_details": "Backup job <JobName> has been started by user <UserName>",
        "severity": "Info",
        "mitre_tactic": "",
        "mitre_technique": "",
        "nist_800_53r5": "",
        "parameters": 'JobSessionID="abc";JobID="def"',
    }]
    out_path = tmp_path / "out.csv"
    write_csv(events, str(out_path))
    content = out_path.read_text()
    lines = content.splitlines()
    assert lines[0] == ",".join(FIELDS)
    assert "parameters" in FIELDS
    assert 'JobSessionID=""abc"";JobID=""def""' in lines[1] or 'JobSessionID=\\"abc\\"' in lines[1] or "abc" in lines[1]
