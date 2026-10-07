# Incident 001 — Authorized lab port scan

**Case status: documentation draft; supporting screenshots and exact event measurements pending.**

## Summary

The author previously generated scan traffic from Kali Linux and reviewed pfSense firewall events in Splunk. This case structures that exercise as an analyst investigation. The revised detection and scheduled alert have not yet been validated against the live lab.

## Case details

| Field | Value |
| --- | --- |
| Environment | VirtualBox SOC home lab |
| Source machine | Kali Linux |
| Source IP | Pending actual event evidence |
| Target IP | 192.168.10.100 in the reported addressing; verify against events |
| Start / end and timezone | Pending |
| Source telemetry | pfSense filterlog |
| SIEM | Splunk; index `pfSense` |
| Distinct destination ports | Pending |
| Firewall action | Pending raw-event review |
| Triggered alert / search job | Pending |
| Analyst | xFcyber |

## Detection

The [analytic](../detections/port-scan-detection.md) extracts IPv4 TCP addresses and ports, then looks for at least five destination ports per source/destination pair in the selected five-minute window. This is a scan candidate and needs context.

## Evidence register

| Evidence | Required content | Status |
| --- | --- | --- |
| E01 | Kali command/output, IP and timestamp | Not attached |
| E02 | pfSense interface and matching logged rule | Not attached |
| E03 | Sanitized raw firewall events | Not attached |
| E04 | SPL and parsed source/destination/port table | Not attached |
| E05 | Candidate result with unique ports and event count | Not attached |
| E06 | Scheduled job and Triggered Alerts result, if enabled | Not attached |

Add sanitized images under [screenshots](../screenshots/README.md), then link only files that actually exist.

## Investigation steps

1. Locate raw events in the exact exercise time range.
2. Check extracted fields against CSV values.
3. Match the source IP to Kali and the destination IP to the test target.
4. Review ports and action; distinguish attempted discovery from successful access.
5. Match event times to the authorized scan record.
6. Record the candidate result and any observed alert.
7. Check for other events only if they are actually collected; avoid inferring endpoint activity from firewall logs alone.

## Verdict

**Provisional: scan-like activity consistent with the authorized lab exercise.**

Finalize as **True Positive for scan behavior — authorized lab simulation** only after the events and command record agree. Authorization changes the incident context; it does not erase a correct behavioral detection. Do not conclude malicious compromise from this evidence alone.

## MITRE ATT&CK

Proposed association: [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/). The mapping describes the discovery behavior, not a finding of malicious intent.

## Response and lessons

The exercise itself does not require containment. Record whether any firewall rule was changed and restore temporary test rules if applicable. In a production investigation, validate ownership and authorization before deciding on containment.

Lessons to demonstrate with evidence: path-dependent visibility, raw-event verification, difference between grouped results and individual events, and limits of threshold-based detection.

