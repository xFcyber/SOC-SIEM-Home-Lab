# Splunk network and startup baseline

## Evidence — 2026-10-07

![Splunk startup output and current network interface](../screenshots/splunk-ip-startup.png)

| Field | Captured value |
| --- | --- |
| VirtualBox VM | Splunk-Server, Running |
| Shell hostname | splunk-server |
| Command | ip -br addr |
| Interface | enp0s3, UP |
| IPv4 | 192.168.10.20/24 |
| Version in installation manifest path | 10.4.3 |
| Daemon startup output | Starting splunk server daemon (splunkd)... Done |
| Local web availability check | http://127.0.0.1:8000 ... Done |
| Advertised web URL | http://splunk-server:8000 |

The current screenshot confirms the server address as 192.168.10.20. Startup output reports that preliminary checks passed, installed files were intact, the daemon started, and the local web availability check completed.

The capture also shows a kernel watchdog message: `BUG: soft lockup - CPU#1 stuck for 44s! [swapper/1:0]`. Its cause is not established. The subsequent network command completed, but this screenshot does not establish sustained service health.

## Validation still needed

- Listening sockets for TCP 8000, TCP 9997 and UDP 5514.
- Remote access to Splunk Web and receiver ports.
- Current endpoint forwarding and firewall syslog destination.
- Newly indexed events from the controlled test.

The server's gateway and clock are not visible. Successful startup and configured indexes do not independently prove current ingestion.
