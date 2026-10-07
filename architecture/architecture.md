# Lab architecture

## Addressing snapshot

These values reflect the previously reported lab arrangement; confirm them against the current VM interfaces.

| System | Lab address | Network role |
| --- | --- | --- |
| pfSense LAN | 192.168.10.1 | SOC-LAB gateway |
| Splunk Ubuntu Server | 192.168.10.20 | Log receiver and search UI |
| Windows 11 | 192.168.10.100 | Monitored endpoint |
| Wazuh service | Dashboard at 192.168.10.10; configured manager endpoint not captured | Endpoint monitoring |
| Scan source, reported as Kali | 192.168.20.100 in firewall screenshots | Attacker segment for this case |
| pfSense attacker interface | Not yet recorded | Routes attacker traffic into SOC-LAB |

Firewall screenshots establish the observed source address. A Kali command/interface screenshot is still needed to confirm the source machine independently. The Wazuh dashboard URL alone does not establish the endpoint configured in the agent.

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
| Splunk receiving | TCP 9997 | Previously configured |
| Splunk Web | TCP 8000 | Previously used |
| Firewall syslog receiver | UDP 5514 | Observed Splunk source udp:5514; sender settings not captured |
| Wazuh agent communication | Confirm from agent/manager configuration | Record actual settings |

The screenshot-supported input is UDP 5514. Confirm sender settings and the actual Wazuh manager endpoint from configuration.

