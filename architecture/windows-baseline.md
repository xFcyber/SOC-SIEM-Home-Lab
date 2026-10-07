# Windows network and clock baseline

## Evidence

![PowerShell IP configuration and clock](../screenshots/windows-ip-time.png)

The original screenshot records these Windows 11 endpoint settings:

| Field | Observed value |
| --- | --- |
| IPv4 address | 192.168.10.100 |
| Subnet mask | 255.255.255.0 (/24) |
| Default gateway | 192.168.10.1 |
| Connection-specific DNS suffix | home.arpa |
| Displayed local date and time | 2026-10-07 14:32:59 |
| Displayed UTC offset | +03:00 |

## Commands captured

```powershell
ipconfig
Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
```

## Interpretation

Windows is configured on the 192.168.10.0/24 subnet with 192.168.10.1 as its default gateway. The displayed offset matches Saudi Arabia's UTC+03:00.

This screenshot does not show successful gateway/Splunk connectivity or the state of Sysmon and forwarding services. A local clock reading does not establish NTP synchronization or agreement with other VMs.

## Next validation

Record Kali's address, route to the Windows endpoint and timestamp, then compare instants using their UTC offsets. Check the actual Splunk server address before testing receiving connectivity.
