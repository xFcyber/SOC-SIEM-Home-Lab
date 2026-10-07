# Firewall syslog forwarding

Firewall logs were previously forwarded to Splunk. Record the receiver's actual protocol and port before reproducing the setup.

| Detail | Value |
| --- | --- |
| Splunk host | Previously reported as 192.168.10.20 |
| Observed receiver input | UDP 5514, from source metadata in raw event screenshot |
| Transport | UDP in the captured receiving metadata; sender settings not attached |
| Log category | Firewall / filterlog |
| Splunk index | Previously used as `pfSense` |

The [raw-event screenshot](../screenshots/splunk-pfsense-raw-events.png) establishes collection and identifies udp:5514. The remote logging settings screen is still needed. Verify both sides and resolve the two timestamp prefixes visible in the captured raw events.

## Verification

1. Generate a small authorized test through a logged rule.
2. Search `index=pfSense "filterlog"` across the recorded time range.
3. Open a raw event; compare its CSV payload with the [parser](../detections/port-scan-detection.md).
4. Confirm the source/destination and action against the test.

Transport health is separate from timestamp accuracy and field extraction. Log prefixes may differ by syslog format; the provided parser seeks the CSV payload at the end of the event.

