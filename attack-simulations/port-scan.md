# Controlled IPv4 TCP port scan

**Historical case:** an earlier Kali scan and firewall event review, with its original command still unavailable.

**New executed exercise:** the 2026-10-07 screenshot captures the actual command and complete output for an eight-port TCP SYN scan. See [case 002](../investigations/incident-002-controlled-port-scan.md).

## Preparation

1. Confirm Windows is currently `192.168.10.100`.
2. Put Kali in the attacker segment for this firewall case.
3. Verify that the path to the target crosses pfSense.
4. Enable logging on the matching firewall rule and confirm syslog ingestion.
5. Record test start/end time and timezone.

## Captured command — 2026-10-07

```bash
sudo nmap -sS -Pn -n -p 22,80,135,139,443,445,3389,5985 --reason -oN soc-port-scan-01.txt 192.168.10.100
```

The run starts at 15:54 UTC+03:00 and completes in 0.34 seconds. Ports 135, 139 and 445 are reported open; the other five are closed. The normal output file itself is still awaiting upload. [Case 002](../investigations/incident-002-controlled-port-scan.md) confirms eight matching firewall records and one grouped manual detection result.

[Original scan screenshot](../screenshots/kali-port-scan.png)

## Later scheduled alert evidence — 2026-10-09

The [original Trigger History screenshot](../screenshots/splunk-port-scan-alert-triggered-20261009-case002.png) shows the enabled **SOC Lab - IPv4 TCP Port Scan** alert firing repeatedly, most recently **18:30:02 UTC (21:30:02 Asia/Riyadh)**. The later [scheduled result screenshot](../screenshots/splunk-port-scan-scheduled-replay-20261009-case002.png) shows the **2026-10-09 18:30 UTC** job replaying the fixed **2026-10-07 12:52–12:57 UTC** window and returning **8 events / 1 grouped result** matching the original scan. No fresh scan is established. Correct the live alert's fixed bounds to the proposed relative window, capture its actual schedule, then run a fresh bounded test and inspect its scheduled results. The correction and fresh validation remain pending.

## Example command

```bash
sudo nmap -sS -Pn -p 22,23,80,135,139,443,445,3389 192.168.10.100
```

Use only the authorized lab target. This command is an example for a future/repeat test, not a transcript of the earlier scan.

## Expected observation, to verify

Splunk should receive logged connection attempts for the scanned ports when routing and logging cover the traffic. Some ports may be filtered or closed. Firewall event counts need not equal scan packet counts.

Search a five-minute time range containing the recorded test with the [analytic](../detections/pfsense-ipv4-port-scan.spl). A candidate requires at least five distinct destination ports for one source/destination pair.

## Evidence

Attach the actual command/output, firewall rule logging, parsed Splunk results and raw events. Record Kali's real IP; do not use an invented address.

