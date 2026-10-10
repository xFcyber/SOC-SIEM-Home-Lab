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

The [original Trigger History screenshot](../screenshots/splunk-port-scan-alert-triggered-20261009-case002.png) shows the enabled **SOC Lab - IPv4 TCP Port Scan** alert firing repeatedly, most recently **18:30:02 UTC (21:30:02 Asia/Riyadh)**. The later [scheduled result screenshot](../screenshots/splunk-port-scan-scheduled-replay-20261009-case002.png) shows the **2026-10-09 18:30 UTC** job replaying the fixed **2026-10-07 12:52–12:57 UTC** window and returning **8 events / 1 grouped result** matching the original scan. That 2026-10-09 job established historical replay only. The later 2026-10-10 execution and scheduler captures below confirm the correction and a fresh controlled result.

## Fresh retest attempt — 2026-10-10

At **11:22:49–11:22:52 +03:00**, the author submitted a new eight-port scan command with `-oN soc-port-scan-20261010.txt`. Nmap **7.94SVN** returned **setup_target: failed to determine route to 192.168.10.100**, followed by **0 hosts scanned**. This was an aborted attempt; no new port states or completed target scan are established.

[Submitted terminal transcript](../investigations/evidence/port-scan-retest-20261010-submitted-terminal.txt) · [Case 002 diagnosis and next steps](../investigations/incident-002-controlled-port-scan.md)

Interface/address/route diagnostics were requested after that aborted attempt. The later completed scan below shows target setup working for the new run; the configuration change itself was not captured. The later fresh scheduler capture below verifies the executed relative-window correction.

## Completed fresh rerun — 2026-10-10

![Fresh completed Nmap scan](../screenshots/kali-port-scan-retest-20261010-case002.png)

The same eight-port command completes at **11:28:25 +03:00 (08:28:25 UTC)**. Nmap reports **1 IP address / 1 host up**, **0.20 seconds** elapsed, ports **135/139/445 open** and **22/80/443/3389/5985 closed**. The native `soc-port-scan-20261010.txt` file is still awaiting upload; the original screenshot is attached unchanged.

The [fresh Trigger History](../screenshots/splunk-port-scan-alert-triggered-20261010-case002.png) records **08:30:02 UTC (11:30:02 Asia/Riyadh)**. The [matching scheduled job](../screenshots/splunk-port-scan-scheduled-results-20261010-case002.png) uses `earliest=-6m@m latest=-1m@m`, covers **08:24–08:29**, and returns **192.168.20.20 → 192.168.10.100**, **8 distinct ports / 8 indexed events**, the exact Nmap port set and **pass**. The [executed scheduled SPL](../detections/pfsense-ipv4-port-scan-scheduled.spl) is attached.

This confirms fresh scheduled detection for the authorized test. The [unchanged raw firewall export](../investigations/evidence/soc-port-scan-events-20261010.csv) contains **8 distinct inbound TCP SYN records** on **em2**, from **192.168.20.20:37074** to **192.168.10.100**, with the exact scanned port set and **pass**. Its records reproduce the scheduled eight-event/eight-port aggregation. Native Nmap output and exact cron/dispatch settings still need capture. The raw records document the firewall interface; the current selected gateway/route and the route-recovery configuration change remain uncaptured. [Raw validation and timestamp limits](../investigations/incident-002-controlled-port-scan.md#evidence-10--original-raw-firewall-csv-reconciled--2026-10-10).

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

