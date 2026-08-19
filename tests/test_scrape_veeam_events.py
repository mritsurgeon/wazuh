from pathlib import Path

from tools.scrape_veeam_events import parse_events_table

FIXTURE = Path(__file__).parent / "fixtures" / "veeam_events_13_sample.html"


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
    }
    for e in events:
        assert set(e.keys()) == expected_keys
