# Windows failed-logon brute-force candidate

**Status:** Five-event manual validation and scheduled firing confirmed. The fresh 2026-10-09 test has captured Trigger History and scheduled View Results.

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

The alert runs every five minutes over the previous five minutes. The query below matches the captured 2026-10-09 scheduled job: it preserves the original event time, groups events into five-minute buckets by source/account, and returns buckets with at least five failures.

```spl
index=security_logs "<EventID>4625</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpPort'>(?<IpPort>[^<]*)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]*)</Data>"
| rex field=_raw "<Data Name='WorkstationName'>(?<WorkstationName>[^<]*)</Data>"
| eval event_time=_time
| bin _time span=5m
| stats count
    min(event_time) as first_seen
    max(event_time) as last_seen
    values(WorkstationName) as Workstation
    values(LogonType) as LogonType
    by _time IpAddress TargetUserName
| where count >= 5
| convert ctime(_time) ctime(first_seen) ctime(last_seen)
| rename _time as detection_window
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

The original 2026-10-08 evidence showed a three-hour difference between some displayed/indexed timestamps and embedded raw timestamps. Clock normalization was not performed during that exercise.

For the fresh 2026-10-09 test, the [original five-event raw CSV](../investigations/evidence/soc-002-4625-events-20261009.csv) provides explicit UTC timestamps: exported `_time` (`+0000`) and embedded Windows `SystemTime` (`Z`) agree within one millisecond for all five records. The distinct EventRecordIDs are **78762–78766**, and the first/last times match the scheduled result. This comparison is specific to the fresh records.

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

The original configuration capture showed no fired events. On **2026-10-09**, a fresh five-attempt test caused **Trigger History** to record **17:50:01 UTC (20:50:01 Asia/Riyadh)**. Its scheduled **View Results** job displays **5 events / 1 grouped result** for **192.168.20.20 / SOC-Test / KALI / LogonType 3** in the **17:45–17:50** window shown by Splunk. Actual first/last event times are **17:48:00.989** and **17:48:07.792** as displayed.

[Trigger History screenshot](../screenshots/splunk-brute-force-alert-triggered-20261009-case003.png) · [Scheduled results screenshot](../screenshots/splunk-brute-force-scheduled-results-20261009-case003.png) · [Full retest evidence](../investigations/incident-003-brute-force.md#evidence-6--fresh-scheduled-alert-validation--2026-10-09).

The fresh-test successful-logon check returns **0 matching Event ID 4624 records** from **192.168.20.20** over **17:45:00–18:04:33 as displayed by Splunk**. This covers the fresh failed batch and is a scoped negative search result. The raw 4625 export independently confirms the failed-authentication fields, including **Status=0xc000006d**, **SubStatus=0xc000006a** and **AuthenticationPackageName=NTLM**. [Successful-logon screenshot](../screenshots/splunk-successful-logon-check-retest-20261009-case003.png) · [Query and exact bounds](../investigations/incident-003-brute-force.md#evidence-7--successful-logon-check-for-the-fresh-retest--2026-10-09).

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
- Fixed five-minute buckets can split a burst across a bucket boundary; the captured test fits within one bucket.
- Late ingestion or skipped scheduled runs can miss events; ingestion delay has not been measured in this test.
- Local failures with no meaningful remote IP should be investigated separately.
- XML extraction depends on the current `renderXml=true` Windows input format.

[Controlled simulation](../attack-simulations/brute-force.md) · [Case 003 investigation](../investigations/incident-003-brute-force.md) · [MITRE T1110](https://attack.mitre.org/techniques/T1110/)
