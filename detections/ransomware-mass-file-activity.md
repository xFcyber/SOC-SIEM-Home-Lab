# Possible ransomware mass file activity

**Status:** Manual detection and scheduled alert firing confirmed.

## Detection goal

Detect a burst of file activity affecting at least ten distinct files with ransomware-like extensions inside one minute.

Primary data source:

- Windows Security Event ID **4663**
- Splunk index: `security_logs`
- Audited path: `C:\Users\Public\SOC-RANSOMWARE-LAB`

MITRE ATT&CK mapping: **T1486 — Data Encrypted for Impact**.

## Query

```spl
index=security_logs
"<EventID>4663</EventID>"
"SOC-RANSOMWARE-LAB"
| rex field=_raw "<Data Name='SubjectUserName'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='ObjectName'>(?<ObjectName>[^<]*)</Data>"
| rex field=_raw "<Data Name='ProcessName'>(?<ProcessName>[^<]*)</Data>"
| where match(lower(ObjectName),"\.(encrypted|locked)$")
| bin _time span=1m
| stats
    count as AccessEvents
    dc(ObjectName) as UniqueFiles
    values(ProcessName) as ProcessName
    by host User _time
| where UniqueFiles >= 10
| sort - UniqueFiles
```

Repository SPL: [ransomware-mass-file-activity.spl](ransomware-mass-file-activity.spl).

## Why distinct files are counted

Event ID 4663 can generate multiple access records for the same object. The analytic therefore uses:

```spl
dc(ObjectName) as UniqueFiles
```

instead of treating raw event count as the number of impacted files.

## Manual validation

The first audited test batch returned:

| Field | Observed value |
| --- | --- |
| Host | `Windows11off` |
| User | `faris` |
| AccessEvents | 20 |
| UniqueFiles | 20 |
| ProcessName | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |

The 20 distinct `.encrypted` files were created within the same minute.

## Alert configuration

The saved Splunk alert is:

`SOC-005 - Possible Ransomware Mass File Activity`

| Setting | Captured value |
| --- | --- |
| Type | Scheduled |
| Cron | `*/5 * * * *` |
| Search window | Last 5 minutes |
| Trigger condition | Number of Results > 0 |
| Trigger mode | Once |
| Action | Add to Triggered Alerts |
| Severity | High |
| Expiration | 24 hours |
| Status | Enabled |

## Scheduled firing validation

After the alert was enabled, a fresh batch of 15 `.locked` files was created in the audited lab directory.

The alert page displayed a **Trigger History** entry at:

```text
2026-10-09 14:20:01 UTC
```

Selecting **View Results** returned one aggregated result from the scheduled job:

| Field | Value |
| --- | --- |
| Host | `Windows11off` |
| User | `faris` |
| AccessEvents | 15 |
| UniqueFiles | 15 |
| ProcessName | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |

This confirms end-to-end scheduled detection.

## Production considerations

This is a lab rule and should not be deployed unchanged. Production logic should avoid relying only on filename extensions and should correlate additional indicators such as:

- high file-write/rename rates,
- multiple directories or shares affected,
- entropy or content changes where available,
- deletion of originals,
- ransom-note creation,
- backup or shadow-copy tampering,
- unusual process ancestry,
- endpoint protection detections,
- network-share impact.

[Simulation](../attack-simulations/ransomware-like-file-activity.md) · [Investigation](../investigations/incident-006-ransomware-like-file-activity.md) · [MITRE T1486](https://attack.mitre.org/techniques/T1486/)
