# SPL searches

Choose a time range that includes the exercise. Index names must match your deployment.

## Historical search evidence

The [captured extraction search](../screenshots/splunk-pfsense-parsed-events.png) is transcribed in [pfsense-field-extraction-observed.spl](pfsense-field-extraction-observed.spl). It lacks a protocol filter; ICMP entries are therefore displayed in port columns. The revised IPv4 TCP searches below avoid that interpretation.

## Raw firewall events

```spl
index=pfSense "filterlog"
| table _time host source sourcetype _raw
```

## Parsed IPv4 TCP events

```spl
index=pfSense "filterlog"
| rex field=_raw "(?<pfdata>[0-9]+,(?:[^,\r\n]*,){7}[46],.*)$"
| eval f=split(pfdata,",")
| where mvindex(f,8)="4" AND lower(mvindex(f,16))="tcp"
| eval interface=mvindex(f,4), action=mvindex(f,6), direction=mvindex(f,7), protocol=lower(mvindex(f,16)), src_ip=mvindex(f,18), dst_ip=mvindex(f,19), src_port=tonumber(mvindex(f,20)), dst_port=tonumber(mvindex(f,21))
| where isnotnull(src_ip) AND isnotnull(dst_ip) AND isnotnull(dst_port)
| table _time interface direction action protocol src_ip dst_ip src_port dst_port _raw
```

Inspect several raw events alongside extracted fields before using the analytic.

## Port scan candidates

Copy [pfsense-ipv4-port-scan.spl](../detections/pfsense-ipv4-port-scan.spl). For ad hoc investigation use a five-minute time range covering the test.

## Why a search displays a count instead of individual events

`stats` transforms events into grouped results. Use the raw or parsed event searches above to inspect evidence. Then filter source/destination to the addresses in the candidate result using Splunk's search UI.

## Endpoint ingestion overview

```spl
index=main source="*Sysmon*"
| table _time host source _raw
```

Adapt the source filter after inspecting metadata. Event ID extractions vary with sourcetype and add-ons, so validate fields before writing Event ID filters.

The historical search has screenshot evidence. The revised searches here were prepared separately and were not executed in the live Splunk instance during repository preparation.

