# Data sources and evidence

| Source | Destination | Prior observation | Next verification |
| --- | --- | --- | --- |
| Sysmon Operational | Splunk `main` via UF | Event ID 1 and forwarding were previously observed | Compare a local event with its indexed copy |
| pfSense filterlog | Splunk `pfSense` via UDP 5514 | Raw and parsed events attached | Resolve timestamp-prefix discrepancy |
| Windows Security | Splunk via UF | Not confirmed as collected | Check inputs and indexed events |
| Windows System / Application | Splunk via UF | Not confirmed as collected | Check each channel separately |
| Windows agent telemetry | Wazuh manager/dashboard | windows-lab (001) active in screenshot | Inspect individual collected event details |

Running an agent service alone does not demonstrate collection, indexing or a security alert.

For each pipeline, retain: source host, channel/input, destination, timestamp, representative sanitized event and a screenshot showing the query or receiving view. Record timezone and compare event time with ingestion time.

Sysmon events depend on its active configuration. The repository does not assume every Sysmon event type is enabled.

