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
- Additional gaps from live validation testing may be documented as Task 10 validation completes.
