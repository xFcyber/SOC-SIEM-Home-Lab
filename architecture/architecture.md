# Lab architecture

## Addressing snapshot

These values reflect the previously reported lab arrangement; confirm them against the current VM interfaces.

| System | Lab address | Network role |
| --- | --- | --- |
| pfSense LAN | 192.168.10.1 | SOC-LAB gateway |
| Splunk Ubuntu Server | 192.168.10.20/24 on enp0s3, confirmed by screenshot on 2026-10-07 | Log receiver and search UI |
| Windows 11 | 192.168.10.100, confirmed by screenshot on 2026-10-07 | Monitored endpoint |
| Wazuh service | Dashboard at 192.168.10.10; configured manager endpoint not captured | Endpoint monitoring |
| Kali, current baseline | 192.168.20.20/24 on eth0, screenshot on 2026-10-07 | Attacker endpoint for the next test |
| Historical scan source, reported as Kali | 192.168.20.100 in 2026-10-04 firewall screenshots | Source of the earlier case |
| Attacker-side next hop | 192.168.20.1 selected by Kali; pfSense interface assignment not independently captured | Route toward SOC-LAB |

The new Kali screenshot establishes its current 192.168.20.20 address and selected route. It does not establish that the same VM owned the historical 192.168.20.100 address; those records remain separate. The Wazuh dashboard URL alone does not establish the endpoint configured in the agent.

## Current Windows baseline

The [Windows screenshot](windows-baseline.md) confirms a /24 mask and default gateway 192.168.10.1, with UTC+03:00 displayed. The [Kali follow-up tests](kali-baseline.md) confirm ICMP reachability to the Windows address. Time synchronization remains unverified.

## Current Kali baseline

The [Kali baseline and follow-up captures](kali-baseline.md) show route selection to 192.168.10.100 via 192.168.20.1 using eth0, followed by successful four-packet pings to both addresses with zero packet loss. The follow-up timezone is Asia/Riyadh; NTP is inactive and synchronization is deferred. The gateway's pfSense interface assignment is still not independently captured.

## Current Splunk baseline

The [Splunk screenshot](splunk-baseline.md) confirms enp0s3 at 192.168.10.20/24 and completed startup/local web checks. A kernel soft-lockup message is also visible; its cause is unknown. A follow-up screenshot confirms splunkd sockets on TCP 8000, TCP 9997 and UDP 5514, bound to 0.0.0.0. Remote access and fresh ingestion remain to be checked.

## VM adapter design

- pfSense has a WAN adapter, a SOC-LAB adapter and a separate attacker adapter.
- Windows and the monitoring servers use VirtualBox Internal Network `SOC-LAB`.
- Kali uses the matching attacker Internal Network for the port scan case.
- pfSense routes the exercise between these segments. Its WAN is the upstream home network.

Document actual adapter modes and internal network names. Keep the test destination on the lab subnet.

## Visibility boundaries

A same-subnet Kali → Windows connection normally stays on the virtual LAN and can bypass pfSense. For firewall evidence, verify Kali's route and ensure the traffic crosses the attacker interface. Firewall rules must log matching traffic; stateful filtering can mean logs represent selected packets rather than every scan packet.

Splunk receives firewall syslog separately from endpoint forwarding. Wazuh is a second collection path; this design does not imply Splunk/Wazuh integration or identical alert coverage.

## Ports

| Service | Port | Status |
| --- | --- | --- |
| Splunk receiving | TCP 9997 | splunkd LISTEN on 0.0.0.0:9997, screenshot 2026-10-07 |
| Splunk Web | TCP 8000 | splunkd LISTEN on 0.0.0.0:8000, screenshot 2026-10-07 |
| Firewall syslog receiver | UDP 5514 | splunkd bound to 0.0.0.0:5514; sender settings not captured |
| Wazuh agent communication | Confirm from agent/manager configuration | Record actual settings |

The screenshot-supported input is UDP 5514. Confirm sender settings and the actual Wazuh manager endpoint from configuration.

