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
- `Veeam_Field_Rules_13.1.xml` — field-specific rules for security-relevant events
  (malware detection, compliance analyzer, credentials, licenses; 71 rules, IDs 132000–132070),
  of which 5 are elevated to level 12 ("Potential IOC") for critical activity:
  malware detected, restore point infected, and malware-exclusion-list add/update/settings.
  Each field rule is chained to its generic counterpart via `if_sid` so one real event
  produces one alert, not two. Named to sort alphabetically **after**
  `Generic_Veeam_rules_13.1.xml` — see Task 10 findings below for why that matters.

## Deploy

```bash
cp decoders_13.1.xml /var/ossec/etc/decoders/
cp Generic_Veeam_rules_13.1.xml Veeam_Field_Rules_13.1.xml /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

The two rule files can be copied in either order — Wazuh loads `/var/ossec/etc/rules/`
alphabetically regardless of copy order, and `Veeam_Field_Rules_13.1.xml` is named to
always sort after `Generic_Veeam_rules_13.1.xml` so its `if_sid` references resolve. Don't
rename either file without checking this ordering still holds (see Task 10 findings).

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
(`Field_Veeam_Rules_13.1.xml`, since renamed `Veeam_Field_Rules_13.1.xml`, had this right).
Combined with bugs 1–3, this meant the generic ruleset could never have fired under any
circumstances pre-Task-10. Fixed by updating all 331 `<decoded_as>` values to
`Veeam MP 13.1`.

After all four fixes, all 49 real captured lines decode via the `Veeam MP 13.1` decoder,
extract the correct `EventID` from `instanceId`, and match the exact correct generic rule
(131000–131330) for their event — 100% accuracy across the sample, spanning 19 distinct
EventIDs including startup/finish pairs, VM restore points, malware detection, config
backup, SureBackup, and restore sessions.

**5. `Field_Veeam_Rules_13.1.xml` sorted alphabetically before `Generic_Veeam_rules_13.1.xml`
in `/var/ossec/etc/rules/`, breaking every `if_sid` reference.** Wazuh's `<rule_dir>` loads
every file in a directory in alphabetical (byte) order, and `if_sid` can only resolve to a
rule ID already registered by an earlier-loaded file — a classic forward-reference problem.
With `F` < `G`, the field rules file always loaded before the generic rules file it
references, so every one of the 71 `if_sid` chains was a forward reference and none of them
ever resolved. `wazuh-analysisd -t` only explicitly warned about a subset (25 of 71 in the
full deployment — the exact count is an artifact of file size/hashing, not meaningful on
its own), but live `wazuh-logtest` testing confirmed **none** of the 71 field rules fired
at runtime, including `if_sid` targets that produced no load-time warning at all (e.g. rule
132034 → `if_sid` 131280 loaded with no warning, yet still never fired). An initial
isolation pass (see git history) misattributed this to `<decoded_as>` breaking cross-file
`if_sid` resolution — that theory happened to fit the data because every isolated test case
built to check it also, incidentally, kept the same F-before-G file-load order; it never
actually controlled for load order as a separate variable. Retested properly this time:
renaming the deployed field-rules file to sort after the generic-rules file (no content
changes at all) made every "not found" warning disappear, and rule 132034 fired correctly
on the very same real captured line that had failed before. Fixed for real, permanently,
by renaming the file to `Veeam_Field_Rules_13.1.xml` in the repo (`V` > `G`, so it always
sorts after `Generic_Veeam_rules_13.1.xml` regardless of deploy/copy order) — a self-sorting
filename is more robust for a future deployer than a copy-order instruction buried in a
README section they might not read.

After fix 5 (the rename), field-rule chaining was retested end to end: `wazuh-analysisd -t`
runs with zero "Signature ID not found" warnings, and `wazuh-logtest` against the real
malware-activity line (EventID 41600) now shows rule 131280 (generic) matching and
escalating correctly to rule 132034 (field, level 12, `mitre.id: ['T1204', 'T1486']`) as
the final alert — exactly the intended one-alert-per-event behavior. Field rules
132000–132070 are confirmed firing correctly, with no remaining known engine limitation.

**Event categories not seen in live traffic** (validated by CSV/decoder-logic review only,
not live-fired): most of the ~310 event IDs outside the 19 exercised above — this test
environment only generates VM backup/restore/malware-scan/config-backup/SureBackup/rescan
traffic organically. Notably untested live: licensing, tenant/Cloud Connect management,
tape jobs, multi-factor auth, KMS, Four-Eyes authorization, and the field-rule-specific
categories (credentials, compliance analyzer detail, exclusions lists) beyond what's
covered by the malware detection events (41600, 41615) that did fire live.
