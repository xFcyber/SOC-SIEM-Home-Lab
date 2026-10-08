# Windows failed-logon brute-force candidate

**Status:** Five-event controlled validation confirmed. Scheduled Splunk alert created and enabled; a fired scheduled alert has not yet been captured.

## Behavior and data

Detect five or more Windows failed authentication events from the same source IP against the same target account within the scheduled search window.

- Windows Event ID: **4625 — An account failed to log on**
- Source index: `security_logs`
- Source: `WinEventLog:Security`
- Sourcetype observed: `XmlWinEventLog:Security`
- Lab threshold: **5 failures / 5 minutes**
- MITRE ATT&CK: **T1110 — Brute Force**

The threshold is intentionally low for lab validation and requires analyst context in real environments.

## Scheduled-search SPL

The alert is intended to run every five minutes over the previous five minutes. Because the search window already defines the interval, the scheduled query does not need a second `bin _time` grouping boundary.

```spl
index=security_logs "<EventID>4625</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpPort'>(?<IpPort>[^<]*)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]*)</Data>"
| rex field=_raw "<Data Name='WorkstationName'>(?<WorkstationName>[^<]*)</Data>"
| stats count min(_time) as first_seen max(_time) as last_seen values(WorkstationName) as Workstation values(LogonType) as LogonType by IpAddress TargetUserName
| where count >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

Repository SPL: [windows-brute-force.spl](windows-brute-force.spl).

## Manual validation result

The validated replay in the lab returned one candidate:

| Field | Observed value |
| --- | --- |
| IpAddress | 192.168.20.20 |
| TargetUserName | SOC-Test |
| count | 5 |
| Workstation | KALI |
| LogonType | 3 |
| first_seen | 2026-10-08 12:48:03.986 as displayed in Splunk |
| last_seen | 2026-10-08 12:48:50.113 as displayed in Splunk |

The lab also showed a three-hour difference between some displayed/indexed timestamps and embedded raw timestamps. Clock normalization was not performed during this exercise, so cross-host time-zone interpretation should remain cautious.

## Alert configuration captured

The Splunk alert was saved as:

`SOC-002 - Brute Force Failed Logon Detection`

Configuration used:

- Alert type: **Scheduled**
- Cron schedule: **`*/5 * * * *`**
- Relative search window: **Last 5 minutes**
- Trigger condition: **Number of Results > 0**
- Action: **Add to Triggered Alerts**
- Severity used in the lab: **Medium**
- Status: **Enabled**

The alert configuration page was captured, but no fired scheduled event was demonstrated at that point. Manual analytic validation and saved-alert configuration are therefore documented separately from scheduled firing.

## Interpretation

A result indicates repeated failed authentication behavior, not a successful compromise. Review:

1. Whether the source is expected.
2. Whether the target account is privileged or sensitive.
3. Whether Event ID 4624 follows from the same source.
4. Firewall or network telemetry for the same source, destination and service.
5. Account lockout or password-reset activity.

## Tuning and limitations

- Administrative mistakes and stale credentials can generate repeated failures.
- A distributed password spray may stay below a per-source threshold.
- Slow attacks can evade a short five-minute window.
- Local failures with no meaningful remote IP should be investigated separately.
- XML extraction depends on the current `renderXml=true` Windows input format.

[Controlled simulation](../attack-simulations/brute-force.md) · [Case 003 investigation](../investigations/incident-003-brute-force.md) · [MITRE T1110](https://attack.mitre.org/techniques/T1110/)
