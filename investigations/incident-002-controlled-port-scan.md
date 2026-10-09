# Case 002 — Controlled Kali TCP port scan

**Status:** Controlled scan, firewall correlation, manual replay and scheduled historical replay confirmed. Fixed replay bounds identified in the 2026-10-09 scheduler job; relative-window correction and fresh validation pending.

## Summary

On 2026-10-07 at 15:54 UTC+03:00, an authorized Nmap SYN scan targeted eight TCP ports on the Windows lab address 192.168.10.100. The captured output reports three open and five closed ports. Eight indexed TCP SYN records match the source/destination pair and scanned ports, all with firewall action pass. A subsequent manual analytic replay returns one scan candidate with eight distinct ports and eight logged events. No compromise or exploitation is established. Later screenshots from 2026-10-09 establish scheduled alert firing and a matching scheduler job. That job retains the fixed 2026-10-07 replay bounds and returns this old scan's eight-port result; it does not demonstrate detection of a new scan.

This is a new exercise, separate from [case 001](incident-001-port-scan.md), whose historical firewall source address was 192.168.20.100.

## Scope and baseline

| Role | Value / evidence |
| --- | --- |
| Scanner VM | kali-linux-2024.2, shown in scan screenshot |
| Kali address | 192.168.20.20/24 in the [earlier baseline](../architecture/kali-baseline.md); confirmed as source IP in the matching firewall records |
| Target | Windows 11 lab address 192.168.10.100 |
| Selected route | Via 192.168.20.1, captured before the scan |
| SIEM | Splunk at 192.168.10.20:8000 |
| Firewall collection | UDP 5514 socket and indexed filterlog records verified before the scan |
| Clock limitation | Kali timezone Asia/Riyadh; synchronization deferred, cross-host drift unmeasured |

## Evidence 1 — Executed command and result

![Actual controlled Nmap scan](../screenshots/kali-port-scan.png)

```bash
sudo nmap -sS -Pn -n -p 22,80,135,139,443,445,3389,5985 --reason -oN soc-port-scan-01.txt 192.168.10.100
```

| Run detail | Captured value |
| --- | --- |
| Nmap version | 7.94SVN |
| Start time displayed | 2026-10-07 15:54 +03 |
| Timestamp precision | Minute in screenshot; exact seconds not visible |
| Target count | 1 IP address |
| Reported elapsed time | 0.34 seconds |
| Reported latency | 0.024 seconds |
| Requested normal output file | soc-port-scan-01.txt |

The original text output has not been uploaded or independently read. The screenshot captures the completed run and command specifying the output file.

| TCP port | State | Nmap service label | Reported reason |
| --- | --- | --- | --- |
| 22 | closed | ssh | reset, TTL 127 |
| 80 | closed | http | reset, TTL 127 |
| 135 | open | msrpc | syn-ack, TTL 127 |
| 139 | open | netbios-ssn | syn-ack, TTL 127 |
| 443 | closed | https | reset, TTL 127 |
| 445 | open | microsoft-ds | syn-ack, TTL 127 |
| 3389 | closed | ms-wbt-server | reset, TTL 127 |
| 5985 | closed | wsman | reset, TTL 127 |

Service labels are Nmap's port labels; no service/version probing was requested. They do not independently identify installed applications or vulnerabilities.

## Analyst interpretation

The SYN-ACK responses support Nmap's open-port classifications for 135, 139 and 445. Reset responses support its closed-port classifications for the other five ports. These states describe this scan at this time, not a universal reachability policy or proof of endpoint compromise.

Because `-Pn` bypasses host discovery, the `Host is up, received user-set` line alone is not a successful ping. The earlier ping evidence and the visible scan responses provide separate reachability observations.

The activity is authorized discovery within the lab. The manual replay correctly identifies the controlled port scan: a true positive for the tested behavior, with an authorized-test disposition. The manual replay alone does not establish a malicious incident or a triggered scheduled alert. T1046 (Network Service Discovery) is a technique association for the exercise, not an assertion of malicious intent.

## Evidence 2 — Matching firewall records in Splunk

![Eight matching TCP SYN records](../screenshots/splunk-port-scan-raw-case002.png)

The captured search uses **Last 24 hours** and returns **8 events**:

```spl
index=pfSense "filterlog" "192.168.20.20" "192.168.10.100" "tcp"
| sort 0 - _indextime
| head 30
```

Manual review of all eight visible filterlog rows establishes the following values:

| Field | Observed value |
| --- | --- |
| Source IP | 192.168.20.20 |
| Destination IP | 192.168.10.100 |
| Source port | 51062 |
| Protocol / IP version | TCP / IPv4 |
| Interface | em2 |
| Firewall action / direction | pass / in |
| TCP flags | S (SYN) |
| Distinct destination ports | 22, 80, 135, 139, 443, 445, 3389, 5985 |
| Splunk metadata | host=192.168.10.1; source=udp:5514; sourcetype=syslog |
| Displayed event time | 2026-10-07 12:54:56.000 PM |
| Raw timestamp prefixes | Oct 7 12:54:56 and Oct 7 15:54:56 |

Each scanned destination port appears once in the visible records. The source/destination pair, exact eight-port set and embedded 15:54 timestamp support correlation with the captured Nmap run. These are indexed firewall records, not a grouped detection result or a fired alert.

The firewall's `pass` action means it allowed the recorded packets. It does not establish that every destination port was open; Nmap separately reports three open and five closed ports.

The screenshot contains timestamp prefixes differing by three hours and does not expose an explicit offset or numeric `_time` / `_indextime` values. Their interpretation remains unverified. Clock synchronization is deferred at the author's request. The original raw-event export is still needed.

## Evidence 3 — Manual detection replay confirmed

![One grouped scan candidate with eight destination ports](../screenshots/splunk-port-scan-result-case002.png)

The executed [replay SPL](incident-002-replay.spl) searches IPv4 TCP inbound records, groups by source and destination, and applies a threshold of five distinct destination ports. It contains no hard-coded scanner or target address.

Although the picker shows **Last 15 minutes**, the search includes `earliest=1791377520 latest=1791377820`. The completed-job banner confirms the actual interval **2026-10-07 12:52:00 PM to 12:57:00 PM**, consistent with the selected five-minute replay window. Splunk reports **8 events** and **Statistics (1)**.

| Result field | Captured value |
| --- | --- |
| src_ip | 192.168.20.20 |
| dst_ip | 192.168.10.100 |
| unique_ports | 8 |
| logged_events | 8 |
| destination_ports | 22, 80, 135, 139, 443, 445, 3389, 5985 |
| firewall_actions | pass |

The grouped values agree with the eight individually reviewed records and the scanned port set. This validates field extraction, grouping and threshold logic for this controlled IPv4 TCP case. The executed display variant omits the optional protocol/source-port fields and first_seen/last_seen columns present in the generic repository SPL; those extra output columns have not been demonstrated by this screenshot.

## Evidence 4 — Scheduled Trigger History captured — 2026-10-09

![SOC Lab IPv4 TCP port-scan alert with multiple scheduled firings](../screenshots/splunk-port-scan-alert-triggered-20261009-case002.png)

| Alert field | Captured value |
| --- | --- |
| Saved alert name | SOC Lab - IPv4 TCP Port Scan |
| Enabled | Yes |
| App / owner | search / off |
| Permissions | Private |
| Alert type | Scheduled; Cron Schedule |
| Trigger condition | Number of Results is > 0 |
| Action | Add to Triggered Alerts |
| Latest visible trigger | 2026-10-09 18:30:02 UTC |
| Same instant in Asia/Riyadh | 2026-10-09 21:30:02 +03:00 |

Multiple fully visible preceding entries recur at roughly five-minute intervals, including **18:25:01**, **18:20:02** and **18:15:02 UTC**. This proves that the scheduled alert fired and recorded trigger history. The row cadence is an observation; the actual cron expression is not visible.

The alert overview alone does not expose the saved SPL, search time bounds or matching source/destination/port values. At this stage, attribution and the cause of repeated triggers were unresolved. Evidence 5 below captures the scheduler job for the latest row and identifies fixed historical replay bounds.

The original PNG is preserved without editing: **366,388 bytes**, SHA-256 `5f6d697181271ba69b418c599124bcb1d6aca245fa5ec7f8eeef254f5fcbde64`.

## Evidence 5 — Scheduled results identify fixed historical replay bounds — 2026-10-09

![Scheduled port-scan results with fixed October 7 epoch bounds](../screenshots/splunk-port-scan-scheduled-replay-20261009-case002.png)

The **View Results** URL contains a `scheduler__off__search__` job identifier with `at_1791570600`. This epoch corresponds to **2026-10-09 18:30:00 UTC**, tying the job to the **18:30:02 UTC** Trigger History row. The green completion indicator and **Statistics (1)** show a completed scheduler result.

The first search line is:

```spl
index=pfSense "filterlog" earliest=1791377520 latest=1791377820
```

| Job / result field | Captured value |
| --- | --- |
| Scheduled launch reference | 2026-10-09 18:30:00 UTC |
| Search start, decoded from earliest | 2026-10-07 12:52:00 UTC |
| Search end, decoded from latest | 2026-10-07 12:57:00 UTC |
| Completed-job displayed window | 10/7/26 12:52:00 PM–12:57:00 PM |
| Events / grouped results | 8 / 1 |
| src_ip | 192.168.20.20 |
| dst_ip | 192.168.10.100 |
| unique_ports / logged_events | 8 / 8 |
| destination_ports | 22, 80, 135, 139, 443, 445, 3389, 5985 |
| firewall_actions | pass |

The visible extraction, IPv4 TCP/inbound filtering, source/destination grouping and threshold match the [historical replay](incident-002-replay.spl). The grouped values and exact port set agree with evidence 2 and 3. Some long search lines are horizontally clipped in the image; it is not treated as a complete plain-text export of the saved-search configuration.

**Diagnosis:** The inspected scheduled job evaluates a fixed five-minute window from **7 October**, although it launches on **9 October**. This supports attributing its result to the old controlled scan. Unchanged historical events can satisfy the trigger on every scheduled run, explaining the repeated-history pattern without requiring a fresh attack. Only this scheduled job's results have been inspected; the other Trigger History rows were not individually opened.

Splunk documents that inline time modifiers take precedence over the time-range picker. Changing the picker alone cannot remove these inline epoch bounds. The effective old interval is also directly confirmed by the completed-job banner. [Official time-modifier reference](https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/specify-time-ranges/specify-time-modifiers-in-your-search).

The original PNG is unchanged: **425,123 bytes**, SHA-256 `9e314af21d12049a56fe5985e667ea60ff6e83ab786fa1e613ad6b9300090e17`.

### Proposed live-alert correction — not yet applied

Update the existing saved alert through **Alerts → Open in Search**, replacing its first line with:

```spl
index=pfSense "filterlog" earliest=-6m@m latest=-1m@m
```

Keep the validated aggregation below it, run the search and use **Save** to update the existing alert. This proposes a five-minute moving window delayed by one minute for ingestion. Capture the actual cron expression and confirm a five-minute schedule; the row cadence alone does not establish the saved expression. Align the saved alert's time settings with the same relative window. [Official alert-editing reference](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.4/view-and-update-alerts/alerts-page).

The correction is guidance, not evidence of a change already made on the user's Splunk instance. A fresh bounded scan, its indexed events and the corrected scheduled result are still required. The fixed [historical replay file](incident-002-replay.spl) remains preserved for reproducibility.

## Disposition and remaining validation

**Behavior verdict:** True positive for the controlled port scan.  
**Activity context:** Authorized lab test.  
**Scheduled alert:** Trigger History and View Results confirm historical replay on 2026-10-09; fixed bounds identified, relative-window correction and fresh-event validation pending.  
**Endpoint compromise:** Not established.

1. Apply the proposed relative-window correction to the existing alert and capture the saved query.
2. Capture its exact cron and time settings; confirm the schedule and search window are aligned.
3. Generate a fresh bounded eight-port scan, record its time and correlate its indexed events with the corrected scheduled job.
4. Export the raw records and attach the original Nmap output for reproducible evidence.

No containment or endpoint change has been performed. Clock synchronization remains deferred. The exercise remains open for relative-window correction, fresh scheduled validation and original event/output exports.

## References

- [Nmap SYN scan](https://nmap.org/book/synscan.html)
- [Nmap normal output](https://nmap.org/book/output-formats-normal-output.html)
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
