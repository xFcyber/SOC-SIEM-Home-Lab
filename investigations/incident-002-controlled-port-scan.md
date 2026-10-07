# Case 002 — Controlled Kali TCP port scan

**Status:** Simulation executed; firewall correlation and detection validation pending.

## Summary

On 2026-10-07 at 15:54 UTC+03:00, an authorized Nmap SYN scan targeted eight TCP ports on the Windows lab address 192.168.10.100. The captured output reports three open and five closed ports. No compromise, exploitation, successful SIEM detection or scheduled alert firing is established by this evidence.

This is a new exercise, separate from [case 001](incident-001-port-scan.md), whose historical firewall source address was 192.168.20.100.

## Scope and baseline

| Role | Value / evidence |
| --- | --- |
| Scanner VM | kali-linux-2024.2, shown in scan screenshot |
| Kali address | 192.168.20.20/24 in the [earlier baseline](../architecture/kali-baseline.md); not printed in this Nmap output |
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

The activity is authorized discovery within the lab. Detection outcome is still pending; do not label this a true-positive SIEM alert before obtaining the analytic result. T1046 (Network Service Discovery) is a technique association for the exercise, not an assertion of malicious intent.

## Evidence 2 — Firewall correlation (pending)

Search for the current Kali and Windows addresses, then inspect actual protocol, direction, action and destination ports:

```spl
index=pfsense "filterlog" "192.168.20.20" "192.168.10.100" "tcp"
| sort 0 - _indextime
| head 30
```

Use All time for initial correlation because event timestamp interpretation remains unresolved. This broad search is an evidence lookup, not the five-minute detection analytic. Matching both IP strings does not establish their direction; verify parsed source and destination fields.

Preserve `_raw`, `_time` and `_indextime`. Earlier records have raw timestamp prefixes differing by three hours; do not apply an assumed correction without validation. Firewall state and rule logging can affect the number of recorded packets.

## Detection and disposition (pending)

1. Confirm firewall records match this run and the scanned ports.
2. Execute the [IPv4 TCP analytic](../detections/pfsense-ipv4-port-scan.spl) in a five-minute interval covering the matching records.
3. Record distinct destination ports, logged event count and pass/block actions. The lab threshold is five distinct ports per source/destination pair.
4. Validate the scheduled alert separately, preserving actual schedule and fired-event evidence.
5. Export raw records and attach the original Nmap output before closing the exercise.

No containment or endpoint change has been performed. Final detection verdict, alert severity and closure remain pending.

## References

- [Nmap SYN scan](https://nmap.org/book/synscan.html)
- [Nmap normal output](https://nmap.org/book/output-formats-normal-output.html)
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
