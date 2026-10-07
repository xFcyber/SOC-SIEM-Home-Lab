# Kali network, route and clock baseline

## Evidence

![Kali network and time commands](../screenshots/kali-ip-route-time.png)

| Field | Captured value |
| --- | --- |
| VM | kali-linux-2024.2 |
| Interface | eth0, UP |
| IPv4 | 192.168.20.20/24 |
| Queried destination | 192.168.10.100 |
| Selected next hop | 192.168.20.1 |
| Selected source | 192.168.20.20 |
| Displayed timestamp | 2026-10-07T08:00:35-04:00 |
| Equivalent UTC instant | 2026-10-07T12:00:35Z |
| Equivalent Saudi time | 2026-10-07T15:00:35+03:00 |

## Commands captured

```bash
ip -br addr
ip route get 192.168.10.100
date --iso-8601=seconds
```

## Interpretation

The selected route uses a gateway rather than direct delivery on Windows' subnet. The follow-up ping captures below confirm reachability to the next hop and Windows address. The gateway's pfSense interface assignment still requires separate evidence.

The initial Kali capture uses a different timezone offset from the Windows screenshot. The timestamp's UTC-04:00 value converts to 15:00:35 at UTC+03:00. This does not establish a clock fault or NTP synchronization. The Windows and Kali captures were taken at different times and cannot measure cross-host clock drift.

The follow-up capture below shows Asia/Riyadh. A timezone change changes display rather than the underlying instant.

## Timezone follow-up — 2026-10-07

![Kali timedatectl after timezone change](../screenshots/kali-timezone-ntp-inactive.png)

The visible command is `timedatectl`.

| Field | Captured value |
| --- | --- |
| Local time | Wed 2026-10-07 15:12:00 +03 |
| Universal time | Wed 2026-10-07 12:12:00 UTC |
| RTC time | Wed 2026-10-07 12:11:59 |
| Time zone | Asia/Riyadh (+03, +0300) |
| System clock synchronized | no |
| NTP service | inactive |
| RTC in local TZ | no |

The timezone setting is confirmed. At capture time, timedatectl reports no system-clock synchronization and an inactive NTP service. This does not measure the actual clock error, establish synchronization across lab hosts, or identify why NTP is inactive.

Network time synchronization is deferred at the author's request. The lab proceeds with connectivity validation; successful synchronization remains unverified.

## Gateway reachability — 2026-10-07

![Kali ping to selected next hop](../screenshots/kali-gateway-ping.png)

```bash
ping -c 4 192.168.20.1
```

| Field | Captured value |
| --- | --- |
| Destination | 192.168.20.1 |
| Packets transmitted / received | 4 / 4 |
| Packet loss | 0% |
| RTT min / avg / max / mdev (ms) | 4.412 / 25.258 / 75.238 / 28.975 |

The selected next hop responds to ICMP echo requests from Kali. This establishes reachability to that address at capture time. The screenshot does not independently identify the responding device as pfSense or establish connectivity to Windows or Splunk.

## Windows reachability — 2026-10-07

![Kali ping to Windows endpoint](../screenshots/kali-windows-ping.png)

```bash
ping -c 4 192.168.10.100
```

| Field | Captured value |
| --- | --- |
| Destination | 192.168.10.100 |
| Packets transmitted / received | 4 / 4 |
| Packet loss | 0% |
| Reply TTL | 127 |
| RTT min / avg / max / mdev (ms) | 6.130 / 7.233 / 8.417 / 0.826 |

The Windows address responds to ICMP echo requests from Kali. Together with the previously captured route via 192.168.20.1, this supports routed connectivity to the lab endpoint. It does not prove TCP service availability, firewall log forwarding, or Splunk indexing. The same screenshot also retains the earlier successful gateway ping output.

## Historical versus current addresses

The earlier firewall screenshots show 192.168.20.100 as the source. This new baseline shows Kali at 192.168.20.20. The old evidence is preserved as recorded; the reason for the address change is not established by this screenshot.

Use the current baseline when documenting the next controlled test, and record the actual command and event results.
