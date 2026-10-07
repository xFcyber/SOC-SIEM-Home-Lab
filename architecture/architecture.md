# Lab architecture

## Addressing snapshot

These values reflect the previously reported lab arrangement; confirm them against the current VM interfaces.

| System | Lab address | Network role |
| --- | --- | --- |
| pfSense LAN | 192.168.10.1 | SOC-LAB gateway |
| Splunk Ubuntu Server | 192.168.10.20 | Log receiver and search UI |
| Windows 11 | 192.168.10.100 | Monitored endpoint |
| Wazuh Ubuntu Server | Not yet recorded | Endpoint manager |
| Kali Linux | Not yet recorded | Attacker segment for firewall tests |
| pfSense attacker interface | Not yet recorded | Routes attacker traffic into SOC-LAB |

Do not assign a guessed address to the Wazuh manager or Kali. Record actual addresses before attaching evidence.

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
| pfSense remote syslog destination | Confirm protocol and port | Record actual input |
| Wazuh agent communication | Confirm from agent/manager configuration | Record actual settings |

Use the syslog input actually configured; do not assume UDP 514 or a Wazuh manager address.

