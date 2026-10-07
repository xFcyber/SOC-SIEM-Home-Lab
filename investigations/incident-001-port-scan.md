# Incident 001 — Scan-like traffic across the lab firewall

**Status: screenshot-backed investigation; revised analytic and scheduled firing remain unverified.**

## Summary

Saved lab screenshots show IPv4 TCP traffic from **192.168.20.100** to **192.168.10.100** on multiple destination ports, collected from pfSense in Splunk. The author previously described the source as Kali and the exercise as authorized lab testing. A command transcript is still missing.

This case demonstrates firewall ingestion and manual field review. The enabled scheduled alert is documented separately from a successful trigger.

## Observed details

| Field | Evidence-supported value |
| --- | --- |
| Analyst | xFcyber |
| Observed source | 192.168.20.100; Kali role based on author context |
| Observed destination | 192.168.10.100 |
| Firewall log host | 192.168.10.1 |
| Input / sourcetype | `udp:5514` / `syslog` |
| Index | `pfSense` |
| Visible interface and direction | `em2`, `in` in raw TCP entries |
| Displayed event timestamp | 2026-10-04 15:57:53 in visible rows; timezone not established |
| Raw search | 19 matching events in a 15-minute search |
| Parsed search | 21 matching events in a different 60-minute search |
| TCP ports visibly represented across the images | 11, 22, 25, 80, 139, 443, 3389 |
| Firewall actions | `pass` and `block` visible in parsed results |
| Scheduled alert | Saved and enabled; screenshot shows no fired events |

The port list is a visible subset, not a computed total. Different search filters/windows explain why the displayed 19 and 21 counts must not be treated as one measurement.

## Evidence register

| ID | File | What it proves |
| --- | --- | --- |
| E01 | [Raw firewall events](../screenshots/splunk-pfsense-raw-events.png) | Indexed filterlog entries, addresses, TCP destination ports and receiver metadata |
| E02 | [Parsed event table](../screenshots/splunk-pfsense-parsed-events.png) | An actual extraction search and visible field values |
| E03 | [Enabled alert](../screenshots/splunk-alert-enabled-no-fires.png) | Saved scheduled definition, result-count condition and no displayed fired records |
| E04 | [OPT1 rule draft](../screenshots/pfsense-opt1-rule-pending.png) | An exercise rule exists in configuration; changes were still pending |
| Missing | Kali command/output | Exact command, timing and independent source attribution |
| Missing | Revised analytic result and scheduled job | Live validation of the repository query and a successful firing |

## 1. Raw-event inspection

![pfSense filterlog events indexed in Splunk](../screenshots/splunk-pfsense-raw-events.png)

The visible raw entries show source `192.168.20.100`, destination `192.168.10.100`, IPv4 TCP SYN flags and multiple destination ports. The metadata identifies `host=192.168.10.1`, `source=udp:5514` and `sourcetype=syslog`.

The screenshot also contains two different timestamp prefixes: `Oct 4 15:57:53` and `Oct 4 18:48:28`. Their relationship and timezone are not established. Verify VM clock synchronization and Splunk timestamp parsing before building a precise cross-host timeline.

## 2. Field review

![Observed extraction search and parsed events](../screenshots/splunk-pfsense-parsed-events.png)

The table visibly contains the same source/destination pair, repeated source port `41956` on several TCP rows and destination ports including `443`, `80`, `139` and `11`. A blocked TCP row is also visible. A firewall `pass` record does not demonstrate a successful application connection.

The screenshot's historical search does not restrict records to TCP. Its ICMP rows show values such as `tstamp` and `request` in the `src_port` column, illustrating why protocol-specific parsing matters. Those rows must not be interpreted as TCP ports.

[Historical query transcription](../splunk/pfsense-field-extraction-observed.spl) · [Revised IPv4 TCP analytic](../detections/pfsense-ipv4-port-scan.spl)

The revised analytic groups source/destination pairs over a five-minute search window. These images are not evidence that the revised query was executed or that its grouped result fired an alert.

## 3. Alert state

![Enabled scheduled alert with no displayed fired events](../screenshots/splunk-alert-enabled-no-fires.png)

The screenshot shows **Possible Port Scan Detected**, enabled, scheduled with cron, a **number of results > 0** condition and **Add to Triggered Alerts** action. It also explicitly says **There are no fired events for this alert**.

This supports creation of an alert definition at the captured time. It does not prove successful scheduling, the actual cron expression, the search interval, use of the revised SPL or a triggered record.

## 4. Firewall configuration context

![OPT1 exercise rule with changes awaiting application](../screenshots/pfsense-opt1-rule-pending.png)

The OPT1 page contains **Allow Kali Lab Traffic** and a banner stating that changes must be applied. Treat it as configuration-in-progress evidence. The later raw logs demonstrate observed traffic independently; this image alone does not establish which rule was active when those logs were generated.

## Verdict

**Observed scan-like behavior, consistent with the author's authorized lab simulation.**

The multi-port IPv4 TCP observations support a discovery-pattern finding. Attribution to Kali and authorization rely on the author's exercise context until a command record is added. No successful service access or endpoint compromise is established.

**Scheduled detection outcome: unverified.** The captured alert page contains no fired records.

## MITRE ATT&CK

Behavioral association: [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/). This is a discovery-pattern mapping, not a claim of malicious intent.

## Response and remaining validation

No containment was taken as part of this documentation work. Record any actual lab rule changes separately.

To complete the case: add the real Kali command, confirm clock/timestamp handling, run the revised query over a controlled five-minute test, and capture its grouped result plus any scheduled firing.

## Lessons demonstrated

Raw-event inspection establishes what the source actually logged. Protocol filters prevent ICMP fields from becoming fake TCP ports. Search counts depend on scope. A saved alert and a fired alert provide different evidence.
