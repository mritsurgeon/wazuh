from lxml import etree

from tools.generate_generic_rules import (
    build_rule_xml,
    generate_rules_file,
    severity_to_level,
)


def test_severity_to_level_maps_known_values():
    assert severity_to_level("Info") == 3
    assert severity_to_level("Warning") == 6
    assert severity_to_level("Error") == 8


def test_severity_to_level_defaults_unknown_to_info_level():
    assert severity_to_level("") == 3
    assert severity_to_level("Something Unexpected") == 3


def test_severity_to_level_is_case_insensitive():
    assert severity_to_level("info") == 3
    assert severity_to_level("WARNING") == 6
    assert severity_to_level("eRRoR") == 8


def test_severity_to_level_takes_highest_of_multiple_values():
    # Real data: same event reports at multiple severities depending on outcome.
    # "error" present anywhere in the string wins (worst case).
    assert severity_to_level("Info, Warning, Error") == 8
    assert severity_to_level("Info, Warning") == 6


def test_severity_to_level_substring_match_saves_typo_row():
    # Veeam's own site has a typo ("Waring" instead of "Warning") on one event
    # page. Substring matching means "Waring" alone won't match "warning" --
    # that's a genuine typo, not worth special-casing -- but this particular
    # row also contains "Error", which IS matched via substring, so it still
    # resolves correctly to the worst-case level.
    assert severity_to_level("Info, Waring, Error") == 8


def test_severity_to_level_typo_alone_does_not_match_warning():
    # Confirm the typo truly fails to match "warning" on its own (no "error"
    # present to rescue it) -- falls through to the default info level.
    assert severity_to_level("Waring") == 3


def test_severity_to_level_empty_string_defaults_to_info():
    assert severity_to_level("") == 3


def test_build_rule_xml_contains_event_id_and_description():
    event = {
        "event_id": "31000", "category": "General",
        "message_summary": "General options modified",
        "message_details": "Backup server general options have been changed.",
        "severity": "Info", "mitre_tactic": "", "mitre_technique": "", "nist_800_53r5": "",
    }
    xml = build_rule_xml(event, rule_id=131000)
    root = etree.fromstring(f"<group name='test'>{xml}</group>")
    rule = root.find("rule")
    assert rule.get("id") == "131000"
    assert rule.get("level") == "3"
    assert rule.find("field[@name='EventID']").text == "31000"
    assert rule.find("decoded_as").text == "Veeam MP"


def test_build_rule_xml_uses_worst_case_level_for_multi_severity():
    event = {
        "event_id": "31500", "category": "General",
        "message_summary": "Something happened",
        "message_details": "details",
        "severity": "Info, Warning, Error", "mitre_tactic": "", "mitre_technique": "", "nist_800_53r5": "",
    }
    xml = build_rule_xml(event, rule_id=131001)
    root = etree.fromstring(f"<group name='test'>{xml}</group>")
    rule = root.find("rule")
    assert rule.get("level") == "8"


def test_generate_rules_file_produces_well_formed_xml_with_unique_sequential_ids(tmp_path):
    csv_content = (
        "event_id,category,message_summary,message_details,severity,"
        "mitre_tactic,mitre_technique,nist_800_53r5\n"
        "31000,General,General options modified,details,Info,,,\n"
        "31100,General,Network traffic rules updated,details,Warning,,,\n"
    )
    csv_path = tmp_path / "events.csv"
    csv_path.write_text(csv_content)
    output_path = tmp_path / "rules.xml"

    generate_rules_file(str(csv_path), str(output_path), start_id=131000)

    tree = etree.parse(str(output_path))
    rules = tree.findall(".//rule")
    assert len(rules) == 2
    assert [r.get("id") for r in rules] == ["131000", "131001"]
