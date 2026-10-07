# Firewall syslog forwarding

Firewall logs were previously forwarded to Splunk. Record the receiver's actual protocol and port before reproducing the setup.

| Detail | Value |
| --- | --- |
| Splunk host | Previously reported as 192.168.10.20 |
| Destination syslog port | To confirm |
| Transport | To confirm |
| Log category | Firewall / filterlog |
| Splunk index | Previously used as `pfSense` |

Verify both sides: pfSense remote logging settings and the receiving input. Keep time synchronized on the VMs.

## Verification

1. Generate a small authorized test through a logged rule.
2. Search `index=pfSense "filterlog"` across the recorded time range.
3. Open a raw event; compare its CSV payload with the [parser](../detections/port-scan-detection.md).
4. Confirm the source/destination and action against the test.

Transport health is separate from timestamp accuracy and field extraction. Log prefixes may differ by syslog format; the provided parser seeks the CSV payload at the end of the event.

