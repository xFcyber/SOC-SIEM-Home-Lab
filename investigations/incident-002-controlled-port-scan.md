# Case 002 — Controlled Kali TCP port scan

**Status:** Fresh controlled scan and corrected relative-window scheduled detection confirmed on 2026-10-10. Trigger History at 08:30:02 UTC and View Results match 8 distinct ports / 8 indexed events. The unchanged eight-row raw firewall export reproduces the scheduled aggregation. Native Nmap output and exact cron capture remain pending.

## Summary

On 2026-10-07 at 15:54 UTC+03:00, an authorized Nmap SYN scan targeted eight TCP ports on the Windows lab address 192.168.10.100. The captured output reports three open and five closed ports. Eight indexed TCP SYN records match the source/destination pair and scanned ports, all with firewall action pass. A subsequent manual analytic replay returns one scan candidate with eight distinct ports and eight logged events. No compromise or exploitation is established. Later screenshots from 2026-10-09 establish scheduled alert firing and a matching scheduler job. That job retains the fixed 2026-10-07 replay bounds and returns this old scan's eight-port result; it does not demonstrate detection of a new scan. A later original capture confirms a completed fresh scan at **2026-10-10 11:28:25 +03:00 (08:28:25 UTC)**, with three open and five closed ports. Its indexed aggregation and corrected relative-window scheduled result are captured in evidence 8 and 9 below, completing the fresh scheduled validation. Evidence 10 preserves the original raw CSV and reconciles its eight individual records with the scheduled result.

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

### Live-alert correction identified after the historical replay

Update the existing saved alert through **Alerts → Open in Search**, replacing its first line with:

```spl
index=pfSense "filterlog" earliest=-6m@m latest=-1m@m
```

Keep the validated aggregation below it, run the search and use **Save** to update the existing alert. This proposes a five-minute moving window delayed by one minute for ingestion. Capture the actual cron expression and confirm a five-minute schedule; the row cadence alone does not establish the saved expression. Align the saved alert's time settings with the same relative window. [Official alert-editing reference](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.4/view-and-update-alerts/alerts-page).

At this historical-replay stage, the correction was guidance only. The later execution and scheduler captures in evidence 7–9 confirm the fresh test and the executed relative bounds. Evidence 10 supplies the individual raw-event export for the fresh test. The fixed [historical replay file](incident-002-replay.spl) remains preserved for reproducibility.

## Evidence 6 — Fresh retest aborted during target-route setup — 2026-10-10

Source: [user-submitted terminal transcript](evidence/port-scan-retest-20261010-submitted-terminal.txt), preserved as text. This is a pasted terminal record, not an uploaded screenshot or the native Nmap normal-output file.

The submitted command was:

```bash
date -Is
sudo nmap -sS -Pn -n -p 22,80,135,139,443,445,3389,5985 --reason -oN soc-port-scan-20261010.txt 192.168.10.100
date -Is
```

| Observation | Submitted value |
| --- | --- |
| Before command | 2026-10-10T11:22:49+03:00 |
| After command | 2026-10-10T11:22:52+03:00 |
| Same interval in UTC | 2026-10-10 08:22:49–08:22:52 UTC |
| Nmap version | 7.94SVN |
| Target-route error | setup_target: failed to determine route to 192.168.10.100 |
| Completed scan count | 0 IP addresses (0 hosts up) |
| Nmap reported elapsed time | 0.07 seconds |

The target scan did not complete. Nmap's target-setup code emits this error when its route lookup fails. The output does not identify whether the underlying issue is interface state, missing IPv4 configuration, the routing table or Nmap's route selection. At this aborted-attempt stage, no current interface/address/route diagnostic output had been supplied. The later successful run in evidence 7 establishes that target setup and scanning worked at that time, while the actual network change remains uncaptured. [Nmap target-setup source](https://github.com/nmap/nmap/blob/master/targets.cc).

No port states or fresh scheduled result are established by this attempt. At that failed-attempt stage, updated saved-alert settings had not been supplied. Evidence 9 later confirms the corrected bounds in the executed scheduler job. The native `soc-port-scan-20261010.txt` file itself has not been received.

Diagnostic commands requested after the aborted attempt:

```bash
ip -br addr
ip route
ip route get 192.168.10.100
nmcli device status
```

These inspect current interface addresses, routes, target-route selection and NetworkManager device state. Their outputs and any network configuration changes have not been attached to this investigation. The later completed scan below is the current execution state.

## Evidence 7 — Fresh completed eight-port scan — 2026-10-10

![Fresh completed Kali scan of the Windows lab target](../screenshots/kali-port-scan-retest-20261010-case002.png)

```bash
date -Is
sudo nmap -sS -Pn -n -p 22,80,135,139,443,445,3389,5985 --reason -oN soc-port-scan-20261010.txt 192.168.10.100
date -Is
```

| Run field | Captured value |
| --- | --- |
| Before and after command timestamps | 2026-10-10T11:28:25+03:00 |
| Same displayed second in UTC | 2026-10-10 08:28:25 UTC |
| Nmap version | 7.94SVN |
| Target | 192.168.10.100 |
| Target / host count | 1 IP address / 1 host up |
| Reported scan elapsed time | 0.20 seconds |
| Reported latency | 0.031 seconds |
| Requested normal-output filename | soc-port-scan-20261010.txt |
| Current source IP / gateway | Not visible in this capture |

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

The run completes and reports responses for all eight selected ports, resolving the immediate target-setup failure for this attempt. The screenshot does not show which network setting changed, whether that change persists across reboots or whether the current route traverses pfSense. Those details are not inferred from scan success.

Because `-Pn` bypasses host discovery, the user-set host-up line is not an independent ping result; the visible SYN-ACK/reset responses provide reachability evidence. Service labels are port labels, not service/version identification. The observed open/closed states match the earlier scan, but are recorded as a separate new execution.

The original PNG is unchanged: **352,100 bytes**, SHA-256 `803719a54346c6ee580c33847a1959f8beaf785e8edabf68819a2da38869a8ed`. The native Nmap output file has not been received.

## Evidence 8 — Fresh scheduled Trigger History confirmed — 2026-10-10

![Port-scan alert records the fresh controlled test](../screenshots/splunk-port-scan-alert-triggered-20261010-case002.png)

| Alert field | Captured value |
| --- | --- |
| Name | SOC Lab - IPv4 TCP Port Scan |
| Enabled | Yes |
| App / owner / permissions | search / off / Private |
| Type | Scheduled; Cron Schedule |
| Trigger condition | Number of Results > 0 |
| Action | Add to Triggered Alerts |
| Fresh trigger time | 2026-10-10 08:30:02 UTC |
| Same instant in Asia/Riyadh | 2026-10-10 11:30:02 +03:00 |
| Modified field, as displayed | Oct 10, 2026 8:20:28 AM |

The fresh history row follows the **11:28:25 +03:00** scan. The modified field has no explicit offset, so it is retained as displayed. Older trigger rows remain in the history; their presence is not treated as repeated fresh attacks or proof that the old bounds remain active.

The original PNG is unchanged: **290,744 bytes**, SHA-256 `6aef95f322760eba5e2bd97e29da375835867ecceb8c93a9fabd830a907281d8`.

## Evidence 9 — Corrected relative-window scheduler result confirmed — 2026-10-10

![Fresh scheduler result contains the matching eight-port candidate](../screenshots/splunk-port-scan-scheduled-results-20261010-case002.png)

The **View Results** URL contains a `scheduler__off__search__` identifier with `at_1791621000`, corresponding to **2026-10-10 08:30:00 UTC**. This matches the **08:30:02 UTC** Trigger History row. The search is completed and shows **8 events / Statistics (1)**.

The fully visible query is transcribed in [the executed scheduled SPL](../detections/pfsense-ipv4-port-scan-scheduled.spl). Its first line is:

```spl
index=pfSense "filterlog" earliest=-6m@m latest=-1m@m
```

The core extraction, IPv4 TCP/inbound filtering, grouping and five-port threshold remain the same as the historical replay; only its fixed time bounds were replaced with relative bounds. Unlike the generic extended query, this executed variant does not output first_seen/last_seen or optional protocol/source-port fields.

| Job / result field | Captured value |
| --- | --- |
| Scheduler launch reference | 2026-10-10 08:30:00 UTC |
| Fresh Trigger History time | 2026-10-10 08:30:02 UTC |
| Completed-job displayed window | 2026-10-10 08:24:00–08:29:00 |
| Executed earliest / latest | -6m@m / -1m@m |
| Events / grouped results | 8 / 1 |
| src_ip | 192.168.20.20 |
| dst_ip | 192.168.10.100 |
| unique_ports / logged_events | 8 / 8 |
| destination_ports | 22, 80, 135, 139, 443, 445, 3389, 5985 |
| firewall_actions | pass |

The window is consistent with the scheduler's UTC launch reference and contains the scan's **08:28:25 UTC** displayed time. The source/target pair, exact eight-port set and indexed aggregation support correlation with the fresh run. This establishes **scheduled detection of the controlled scan after the relative-window correction**, rather than another replay of 7 October data.

The **pass** field describes firewall permission for the logged traffic. Nmap separately reports three open and five closed ports. Neither result establishes exploitation or endpoint compromise.

The screenshot validates one fresh test. It does not expose the exact cron expression, dispatch-time settings, suppression options or the individual raw records; the latter are supplied separately in evidence 10. Current interface/gateway details and the earlier route-recovery configuration change also remain uncaptured. The generic query's optional columns and broader input/negative-case coverage are not claimed as validated by this result.

The original PNG is unchanged: **326,484 bytes**, SHA-256 `a50b24df097750b3c03fc6bf33c2d3eb37b17f4ed97dcb8c0c663fd6c5d8df25`.

## Evidence 10 — Original raw firewall CSV reconciled — 2026-10-10

Source: [soc-port-scan-events-20261010.csv](evidence/soc-port-scan-events-20261010.csv), uploaded unchanged. The file contains **8 rows / 25 columns**, preserving `_raw`, explicit UTC `_time` values and Splunk metadata. All eight raw entries are distinct, and each scanned destination port appears once.

The separate source-event search requested for the completed scheduler job's evidence window was:

```spl
index=pfSense "filterlog" earliest=1791620640 latest=1791620940 "192.168.20.20" "192.168.10.100" "tcp"
```

The fixed epochs select **2026-10-10 08:24:00–08:29:00 UTC** for reproducibility. They are specific to this evidence export; the live scheduled SPL retains its relative bounds.

| Field / reconciliation | Observed value |
| --- | --- |
| Records / distinct raw entries | 8 / 8 |
| Source IP → destination IP | 192.168.20.20 → 192.168.10.100 |
| Source port | 37074 on all eight entries |
| Destination ports | 22, 80, 135, 139, 443, 445, 3389, 5985; each once |
| Protocol / IP version | TCP, protocol ID 6 / IPv4 |
| Interface / reason | em2 / match |
| Firewall action / direction | pass / in on all entries |
| TCP flags / data length | S (SYN) / 0 |
| `_time` on all entries | 2026-10-10T08:28:32.000+0000 |
| Host / source / sourcetype | 192.168.10.1 / udp:5514 / syslog |
| CSV index / Splunk server | pfsense / splunk-server |
| Raw timestamp prefixes | Oct 10 08:28:32 and Oct 10 11:28:32 |
| Analytic groups passing the five-port threshold | 1 |
| Reproduced unique_ports / logged_events / firewall_actions | 8 / 8 / pass |

The scheduled analytic's payload extraction and IPv4 TCP/inbound filters accept all eight exported rows. Grouping by source and destination independently reproduces **one candidate with 8 distinct ports, 8 logged events and pass**, matching evidence 9. The addresses and exact eight-port set also match the controlled run. The raw records now establish the firewall observation on **em2**; the selected Kali gateway and the configuration change that repaired the earlier route are still not captured. The export's index metadata is lowercase `pfsense`; the executed SPL is preserved as shown with `index=pfSense`.

The CSV's explicit `_time` is **08:28:32 UTC**, seven seconds after the scan screenshot's displayed **08:28:25 UTC**. This is an observed timestamp difference, not a measured ingestion delay: `_indextime` is absent from the export and cross-host clock synchronization has not been established. The two raw prefixes differ by three hours without explicit offsets; `date_zone=local` does not establish the originating hosts' timezone configuration. The filterlog tracker `1791128736` is a rule tracking ID, not an event timestamp. [Official filterlog field specification](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html).

Original-file integrity: **3,498 bytes**; SHA-256 `36bd9e22aba0e4a81daa514ac30b319b7f6b8fae604442906d5098dea391f8ee`; Git blob SHA `8338770df40c09451d8347437e08190b3bec94ce`. No values, row order, quoting or line endings were changed.

## Disposition and remaining validation

**Behavior verdict:** True positive for the controlled port scan.  
**Activity context:** Authorized lab test.  
**Scheduled alert:** Fresh Trigger History and matching relative-window View Results confirmed on 2026-10-10 at 08:30:02 UTC.  
**Endpoint compromise:** Not established.

1. Upload the native `soc-port-scan-20261010.txt` Nmap output.
2. Capture the exact cron, dispatch-time settings and suppression configuration.
3. Record the current selected gateway/route and the network change behind the recovered scan route when available.

Fresh scan execution, the relative-window correction, matching scheduled detection and raw-record reconciliation are validated for this authorized test. Remaining work is native Nmap output and additional configuration capture. Clock synchronization remains deferred; the route-recovery change and its persistence remain undocumented.

## References

- [Nmap SYN scan](https://nmap.org/book/synscan.html)
- [Nmap normal output](https://nmap.org/book/output-formats-normal-output.html)
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
