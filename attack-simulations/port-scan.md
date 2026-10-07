# Controlled IPv4 TCP port scan

**Previously performed:** a Kali scan and firewall event review. The command below is a reproducible example; the original command and exact output have not been attached.

## Preparation

1. Confirm Windows is currently `192.168.10.100`.
2. Put Kali in the attacker segment for this firewall case.
3. Verify that the path to the target crosses pfSense.
4. Enable logging on the matching firewall rule and confirm syslog ingestion.
5. Record test start/end time and timezone.

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

