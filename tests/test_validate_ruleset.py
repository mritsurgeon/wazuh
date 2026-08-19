from pathlib import Path
from tools.validate_ruleset import (
    check_well_formed, check_unique_ids, check_id_ranges,
    check_event_coverage, check_if_sid_resolves,
)

def write(path: Path, content: str) -> str:
    path.write_text(content)
    return str(path)

def test_check_well_formed_flags_broken_xml(tmp_path):
    bad = write(tmp_path / "bad.xml", "<group><rule id='1'></group>")  # unclosed rule
    errors = check_well_formed([bad])
    assert errors and "bad.xml" in errors[0]

def test_check_well_formed_passes_valid_xml(tmp_path):
    good = write(tmp_path / "good.xml", "<group><rule id='1'></rule></group>")
    assert check_well_formed([good]) == []

def test_check_unique_ids_flags_duplicates_across_files(tmp_path):
    a = write(tmp_path / "a.xml", "<group><rule id='131000' level='3'></rule></group>")
    b = write(tmp_path / "b.xml", "<group><rule id='131000' level='4'></rule></group>")
    errors = check_unique_ids([a, b])
    assert any("131000" in e for e in errors)

def test_check_id_ranges_flags_out_of_range_ids(tmp_path):
    generic = write(tmp_path / "g.xml", "<group><rule id='999' level='3'></rule></group>")
    field = write(tmp_path / "f.xml", "<group><rule id='132000' level='4'></rule></group>")
    errors = check_id_ranges(generic, field)
    assert any("999" in e for e in errors)

def test_check_event_coverage_flags_missing_event_id(tmp_path):
    generic = write(tmp_path / "g.xml",
        '<group><rule id="131000" level="3"><field name="EventID">31000</field></rule></group>')
    csv_path = write(tmp_path / "events.csv",
        "event_id,category,message_summary,message_details,severity,mitre_tactic,mitre_technique,nist_800_53r5\n"
        "31000,General,x,x,Info,,,\n"
        "31100,General,y,y,Info,,,\n")
    errors = check_event_coverage(generic, csv_path)
    assert any("31100" in e for e in errors)

def test_check_if_sid_resolves_flags_dangling_reference(tmp_path):
    generic = write(tmp_path / "g.xml", "<group><rule id='131000' level='3'></rule></group>")
    field = write(tmp_path / "f.xml",
        "<group><rule id='132000' level='6'><if_sid>131999</if_sid></rule></group>")
    errors = check_if_sid_resolves(field, generic)
    assert any("131999" in e for e in errors)

def test_check_if_sid_resolves_flags_field_to_field_reference(tmp_path):
    # if_sid must resolve against the generic rules file specifically — a field
    # rule referencing another field rule's id is not a valid chain in this
    # design (Task 8: one field rule -> its one generic counterpart, no
    # field-to-field), even though 132001 really exists in field.xml.
    generic = write(tmp_path / "g.xml", "<group><rule id='131000' level='3'></rule></group>")
    field = write(tmp_path / "f.xml",
        "<group>"
        "<rule id='132001' level='6'></rule>"
        "<rule id='132002' level='8'><if_sid>132001</if_sid></rule>"
        "</group>")
    errors = check_if_sid_resolves(field, generic)
    assert any("132001" in e for e in errors)
