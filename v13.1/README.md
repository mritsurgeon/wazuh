# Veeam Backup & Replication 13.1 — Wazuh Integration

Standalone decoder/rule set for VBR 13.1, generated from Veeam's official event
ID list (helpcenter.veeam.com/docs/vbr/events/event_id_list.html?ver=13).

## Files

- `veeam_events_13.1.csv` — source of truth, 331 events. Scraped from Veeam's docs via
  `tools/scrape_veeam_events.py` using a two-stage process: first fetching the summary
  event table, then scraping each event's individual detail page for real severity,
  category, message template, and parameter data (fetches ~332 pages total, rate-limited).
  Regenerate if Veeam updates the page.
- `decoders_13.1.xml` — syslog decoders for VBR 13.1's structured-data format.
- `Generic_Veeam_rules_13.1.xml` — one rule per event ID (331 rules, IDs 131000–131330;
  level set by severity).
- `Field_Veeam_Rules_13.1.xml` — field-specific rules for security-relevant events
  (malware detection, compliance analyzer, credentials, licenses; 71 rules, IDs 132000–132070),
  of which 5 are elevated to level 12 ("Potential IOC") for critical activity:
  malware detected, restore point infected, and malware-exclusion-list add/update/settings.
  Each field rule is chained to its generic counterpart via `if_sid` so one real event
  produces one alert, not two.

## Deploy

```bash
cp decoders_13.1.xml /var/ossec/etc/decoders/
cp Generic_Veeam_rules_13.1.xml Field_Veeam_Rules_13.1.xml /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

## Rule IDs

- Generic rules: 131000–131330
- Field-specific rules: 132000–132070

Non-overlapping with the v12.1 set (100000s), so both can run on the same
manager at once if needed.

## Known gaps

- Event IDs 210, 290, 40210, 40290 have no detail page on Veeam's documentation site (404 errors).
  These four events appear in the generic rule set with baseline data only, not enriched
  severity/category/parameter information.

### Task 10 live validation findings

Tested against a real VBR 13.1 test server (`13.1.1.18`) feeding a live Wazuh test manager
over syslog, using 49 real captured lines spanning 19 distinct event IDs pulled from
`/var/ossec/logs/archives/`. Before this task, the decoder had never actually been deployed
and exercised against real traffic — three bugs below meant it silently decoded nothing.

**1. The base decoder's prematch never matched any real event.** It required the literal
text `Veeam_MP - - [categoryId=` to appear contiguously, but the real wire format always
inserts an RFC 5424 structured-data block and a severity token in between:
`Veeam_MP - - [origin enterpriseId="31023"] [INF] [categoryId=0 instanceId=42200 ...]`.
Fixed by anchoring the prematch on `Veeam_MP - - [origin` instead.

**2. `categoryId` is always `0` on the wire — the real event number is in `instanceId`.**
The pre-Task-10 decoder named its captured field `EventID` but populated it from
`categoryId`'s value (always `0`), so no generic or field rule could ever match a specific
event even once the prematch was fixed — every event would have decoded to `EventID=0`.
Fixed: `EventID` is now populated from `instanceId`'s value. The severity token
(`INF`/`WRN`/`ERR`) is also now captured as a new `Severity` field, since it's real,
directly-available data from the wire format independent of the CSV's scraped severity.

**3. `<field name="EventID">` matches were unanchored substrings.** Wazuh's rule field
matching is regex-based by default, not exact-equality. With plain numeric values like
`<field name="EventID">200</field>`, an event with `EventID=42200` (which *ends in* "200")
would incorrectly match the rule looking for event 200 — confirmed live: EventID 42200
(Malware Detection Session Started) was firing rule 131023 ("Tape Copy Job Finished",
EventID 200) instead of its own rule 131289. Fixed by anchoring every generic rule's
EventID field to `^NNNNN$` (all 331 rules); `tools/validate_ruleset.py`'s coverage check
was updated to strip the anchors before comparing against the CSV's plain numeric IDs.

**4. `Generic_Veeam_rules_13.1.xml` referenced the wrong decoder name.** All 331 rules used
`<decoded_as>Veeam MP</decoded_as>`, but the decoder is named `Veeam MP 13.1`
(`Field_Veeam_Rules_13.1.xml` had this right). Combined with bugs 1–3, this meant the
generic ruleset could never have fired under any circumstances pre-Task-10. Fixed by
updating all 331 `<decoded_as>` values to `Veeam MP 13.1`.

After all four fixes, all 49 real captured lines decode via the `Veeam MP 13.1` decoder,
extract the correct `EventID` from `instanceId`, and match the exact correct generic rule
(131000–131330) for their event — 100% accuracy across the sample, spanning 19 distinct
EventIDs including startup/finish pairs, VM restore points, malware detection, config
backup, SureBackup, and restore sessions.

**Known limitation found, not fixable in this ruleset:** on the test manager's Wazuh build
(v4.14.7-rc1), `if_sid` cross-file rule chaining does not work when the parent rule uses
`<decoded_as>`. Isolated with minimal synthetic rules: a same-file `if_sid` chain between
two trivial `<match>`-based rules resolves and fires correctly; the moment the parent rule
adds a `<decoded_as>` constraint (regardless of which decoder, real or synthetic, and
regardless of matching or mismatched `<group>` names between the two rule files), the child
rule's `if_sid` fails to resolve (`wazuh-analysisd -t` warns "Signature ID not found") and,
confirmed via `wazuh-logtest`, the child rule is never even attempted at runtime — the
generic rule fires standalone every time. This affects all 71 rules in
`Field_Veeam_Rules_13.1.xml`, since every one of them uses `decoded_as` (needed to scope
matching to Veeam-decoded events). `wazuh-analysisd -t` only ever surfaces this for a
subset of the 71 as an explicit warning (the count varies with total rule load — 25 of 71
in the full file, more when the file is trimmed smaller) but functional testing shows the
chain doesn't fire for any of them, warned-about or not. This looks like an engine-level
limitation or bug specific to this rc build rather than anything fixable by editing rule
content — worth retesting on a non-rc Wazuh release, or filing upstream. Until resolved,
field rules 132000–132070 should be treated as **not currently firing** on this manager;
the underlying generic rules (131000–131330) still fire correctly and independently for
the same events, so detection coverage is intact at the generic level, just without the
field-rule enrichment/escalation (e.g. malware detection still alerts at its generic level,
just not at the elevated level-12 "Potential IOC" the field rule would apply).

**Event categories not seen in live traffic** (validated by CSV/decoder-logic review only,
not live-fired): most of the ~310 event IDs outside the 19 exercised above — this test
environment only generates VM backup/restore/malware-scan/config-backup/SureBackup/rescan
traffic organically. Notably untested live: licensing, tenant/Cloud Connect management,
tape jobs, multi-factor auth, KMS, Four-Eyes authorization, and the field-rule-specific
categories (credentials, compliance analyzer detail, exclusions lists) beyond what's
covered by the malware detection events (41600, 41615) that did fire live.
