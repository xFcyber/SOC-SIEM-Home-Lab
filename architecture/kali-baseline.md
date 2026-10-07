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

The selected route uses a gateway rather than direct delivery on Windows' subnet. Confirm the gateway's pfSense interface assignment and actual connectivity separately.

Kali currently uses a different timezone offset from the Windows screenshot. The timestamp's UTC-04:00 value converts to 15:00:35 at UTC+03:00. This does not establish a clock fault or NTP synchronization. The Windows and Kali captures were taken at different times and cannot measure cross-host clock drift.

For consistent display, a later step may set Kali's timezone to Asia/Riyadh. A timezone change changes display rather than the underlying instant.

## Historical versus current addresses

The earlier firewall screenshots show 192.168.20.100 as the source. This new baseline shows Kali at 192.168.20.20. The old evidence is preserved as recorded; the reason for the address change is not established by this screenshot.

Use the current baseline when documenting the next controlled test, and record the actual command and event results.
