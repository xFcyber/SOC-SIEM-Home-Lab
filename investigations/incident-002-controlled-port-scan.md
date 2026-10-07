# Case 002 — Controlled Kali TCP port scan

**Status:** Controlled scan, firewall correlation and manual detection replay confirmed; scheduled alert firing pending.

## Summary

On 2026-10-07 at 15:54 UTC+03:00, an authorized Nmap SYN scan targeted eight TCP ports on the Windows lab address 192.168.10.100. The captured output reports three open and five closed ports. Eight indexed TCP SYN records match the source/destination pair and scanned ports, all with firewall action pass. A subsequent manual analytic replay returns one scan candidate with eight distinct ports and eight logged events. No compromise, exploitation or scheduled alert firing is established.

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

The activity is authorized discovery within the lab. The manual replay correctly identifies the controlled port scan: a true positive for the tested behavior, with an authorized-test disposition. It does not establish a malicious incident or a triggered scheduled alert. T1046 (Network Service Discovery) is a technique association for the exercise, not an assertion of malicious intent.

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

## Disposition and remaining validation

**Behavior verdict:** True positive for the controlled port scan.  
**Activity context:** Authorized lab test.  
**Scheduled alert:** Successful firing not yet demonstrated.  
**Endpoint compromise:** Not established.

1. Prepare the scheduled alert using the validated aggregation logic. Remove the fixed `earliest` / `latest` replay values from its query and configure a relative window as described in the [schedule proposal](../splunk/alerts.md).
2. Capture the actual saved query, schedule, time window and trigger action.
3. Generate a fresh controlled scan and inspect the scheduled job and Triggered Alerts. Manual replay does not prove scheduled operation.
4. Export the raw records and attach the original Nmap output for reproducible evidence.

No containment or endpoint change has been performed. Clock synchronization remains deferred. The exercise remains open for scheduled-alert validation and original event/output exports.

## References

- [Nmap SYN scan](https://nmap.org/book/synscan.html)
- [Nmap normal output](https://nmap.org/book/output-formats-normal-output.html)
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
