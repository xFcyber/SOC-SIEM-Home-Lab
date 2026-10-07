# pfSense search validation — 2026-10-07

![pfSense filterlog search in Splunk](../screenshots/splunk-pfsense-search-check.png)

## Captured search

```spl
index=pfSense "filterlog"
| sort 0 - _indextime
| head 10
```

The screenshot uses **Last 24 hours**, not All time. It displays 10 returned events after `head 10`; this is not the total number of available firewall events.

| Field | Observation |
| --- | --- |
| Browser environment | Windows 11 VM |
| Splunk Web | 192.168.10.20:8000 |
| Displayed version | 10.4.3 |
| Host metadata | 192.168.10.1 |
| Source metadata | udp:5514 |
| Sourcetype | syslog |
| Visible program | filterlog |
| Visible firewall interface / action / direction | em0 / block / in |
| Visible transport | UDP |
| Visible event date | 2026-10-07 |

Splunk Web is accessible from the Windows VM, and the search returns indexed firewall data. The visible records describe background UDP broadcast traffic rather than the planned Kali TCP scan. They do not prove a scan detection or alert trigger.

## Timestamp interpretation

The first visible row displays event time 12:45:40, with raw prefixes `Oct 7 12:45:40` and `Oct 7 15:45:40`. Other rows show the same three-hour difference. Neither raw prefix contains an explicit timezone offset. The screenshot does not identify the cause of this difference or display the actual `_indextime` values, despite sorting on that field.

Do not equate the two raw timestamps or infer clock synchronization. Preserve the raw records and compare any new scan using source/destination, ports and index time as well as event time.

## Next exercise

A controlled TCP scan from current Kali 192.168.20.20 to Windows 192.168.10.100 will provide a known event for the [revised analytic](../detections/port-scan-detection.md). Command execution, matching firewall events, analytic output and scheduled firing require their own evidence.
