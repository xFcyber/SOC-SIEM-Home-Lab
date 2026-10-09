# IPv4 TCP port scan candidate

**Status:** Core extraction, grouping and threshold validated by manual and scheduled historical replay. Fixed historical time bounds identified in the saved alert's 2026-10-09 job; relative-window correction and fresh validation pending.

## Behavior and data

Look for five or more distinct TCP destination ports for the same source/destination pair within a five-minute search window. This identifies vertical port scan candidates against one host, not every scan pattern.

Source: pfSense filterlog in Splunk index `pfSense`.

## Field extraction

The query searches for a numeric-rule CSV payload at the end of a log entry, preserving empty comma-separated fields. It then selects IPv4 TCP records.

| CSV index, zero based | Field |
| --- | --- |
| 4 | Interface |
| 6 | Action |
| 7 | Direction |
| 8 | IP version |
| 16 | Protocol text |
| 18 | Source IP |
| 19 | Destination IP |
| 20 | Source port |
| 21 | Destination port |

IPv6 uses a different layout and is intentionally excluded. Compare raw CSV with extracted values before scheduling.

## Query

```spl
index=pfSense "filterlog"
| rex field=_raw "(?<pfdata>[0-9]+,(?:[^,\r\n]*,){7}[46],.*)$"
| eval f=split(pfdata,",")
| where mvindex(f,8)="4" AND lower(mvindex(f,16))="tcp"
| eval interface=mvindex(f,4), action=mvindex(f,6), direction=mvindex(f,7), protocol=lower(mvindex(f,16)), src_ip=mvindex(f,18), dst_ip=mvindex(f,19), src_port=tonumber(mvindex(f,20)), dst_port=tonumber(mvindex(f,21))
| where isnotnull(src_ip) AND isnotnull(dst_ip) AND isnotnull(dst_port)
| where direction="in"
| stats dc(dst_port) as unique_ports count as logged_events values(dst_port) as destination_ports values(action) as firewall_actions min(_time) as first_seen max(_time) as last_seen by src_ip dst_ip
| where unique_ports >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort - unique_ports
```

The earlier draft referenced `src_ip` and `dst_port` without extracting them. This version extracts both and includes the destination IP in grouping. It does not need Kali's IP hard-coded.

## Interpretation

- `unique_ports`: number of distinct destination ports observed.
- `logged_events`: count of matching log entries, not number of successful connections.
- `firewall_actions`: observed pass/block values.
- A candidate requires analyst review and authorization checks.

The search filters inbound records at the logging interface, reducing duplicate direction observations. Confirm that this covers the test route.

## Tuning and limits

Five ports is a deliberately low educational threshold. Legitimate vulnerability scanners and administration can match it. A slow scan split across windows, one-port scans across many hosts, IPv6, UDP, unlogged traffic and same-subnet traffic are outside this analytic's coverage.

Stateful logging may not record every packet. NAT or additional filtering may affect the visible addresses. Confirm the observation point. A missing result is not proof that no scan occurred.

## Observed validation — case 002

The [2026-10-07 controlled scan](../investigations/incident-002-controlled-port-scan.md) has an attached [grouped-result screenshot](../screenshots/splunk-port-scan-result-case002.png). A fixed five-minute [replay](../investigations/incident-002-replay.spl) returns one source/destination pair: **192.168.20.20 → 192.168.10.100**, **8 distinct destination ports**, **8 logged events**, and **pass**. The values match the Nmap port set and individually reviewed firewall records.

The executed variant uses the same extraction, IPv4 TCP/inbound filters, grouping and threshold as the generic query above, while omitting optional protocol/source-port fields and first_seen/last_seen columns. The screenshot validates the core behavior for this one controlled case; it does not demonstrate those extra columns, all input layouts, negative-case coverage or scheduled alert firing.

## Scheduled Trigger History — 2026-10-09

The [original alert-overview screenshot](../screenshots/splunk-port-scan-alert-triggered-20261009-case002.png) shows **SOC Lab - IPv4 TCP Port Scan** enabled and scheduled, with **Number of Results > 0** and **Add to Triggered Alerts**. The latest visible firing is **18:30:02 UTC (21:30:02 Asia/Riyadh)**; earlier rows recur at approximately five-minute intervals.

The overview alone does not expose its SPL, exact cron or search window. The later [View Results screenshot](../screenshots/splunk-port-scan-scheduled-replay-20261009-case002.png) captures a scheduler job launched at **18:30 UTC on 2026-10-09** that still uses `earliest=1791377520 latest=1791377820`. It evaluates **2026-10-07 12:52–12:57 UTC** and returns **8 events / 1 grouped result** matching the old scan's source, destination, port set and **pass** action.

The visible core analytic agrees with the historical replay, while the generic SPL above includes optional output fields not shown in the job result. Fixed replay bounds explain repeated alerts on old data; they do not demonstrate live detection of a new scan. The proposed correction replaces the inline epochs with `earliest=-6m@m latest=-1m@m` and validates a fresh scan under a confirmed five-minute schedule. This has **not yet been applied or validated**. Preserve the historical replay for reproducibility.

[Diagnosis and correction](../investigations/incident-002-controlled-port-scan.md) · [Observed job and schedule proposal](../splunk/alerts.md)

## Validation sequence

1. Run the parsed-event search in [spl-searches.md](../splunk/spl-searches.md).
2. Compare addresses and port values against raw events.
3. Run a recorded controlled scan through pfSense.
4. Search the five-minute interval containing it.
5. Review grouped results against individual events.
6. Attach screenshots and exact observed values to the relevant case: [historical case 001](../investigations/incident-001-port-scan.md) or [controlled case 002](../investigations/incident-002-controlled-port-scan.md).

[Schedule proposal](../splunk/alerts.md) · [CSV specification](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html)
