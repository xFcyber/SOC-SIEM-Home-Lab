# Suspicious Windows scheduled-task creation

**Status:** Windows Event ID 4698 confirmed, Sysmon process execution correlated, and scheduled Splunk alert firing confirmed.

## Detection goal

Identify newly created Windows Scheduled Tasks whose task content launches a command shell or PowerShell.

Primary data source:

- Windows Security Event ID **4698 — A scheduled task was created**
- Splunk index: `security_logs`
- Source: `WinEventLog:Security`
- Sourcetype observed: `XmlWinEventLog:Security`

MITRE ATT&CK mapping: **T1053.005 — Scheduled Task/Job: Scheduled Task**.

## Generic analytic

```spl
index=security_logs
"<EventID>4698</EventID>"
| rex field=_raw "<Data Name='SubjectUserName'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='TaskName'>(?<TaskName>[^<]*)</Data>"
| rex field=_raw "(?s)<Data Name='TaskContent'>(?<TaskContent>.*?)</Data>"
| where match(lower(TaskContent),"cmd\.exe|powershell\.exe|pwsh\.exe")
| table _time User TaskName TaskContent
| sort - _time
```

Repository SPL: [scheduled-task-creation.spl](scheduled-task-creation.spl).

The `(?s)` flag allows the TaskContent extraction to span line breaks in the XML-rendered event.

## Lab validation query

During the controlled test, the alert query also included a lab-specific fallback:

```spl
| search TaskContent="*cmd.exe*" OR TaskContent="*powershell.exe*" OR TaskContent="*pwsh.exe*" OR TaskName="*SOC-LAB*"
```

This ensured the controlled task could validate alert scheduling even if multiline TaskContent extraction was imperfect. The lab-only `TaskName="*SOC-LAB*"` condition should not be used as a production detection.

## Correlated Sysmon evidence

Sysmon Event ID **1 — Process Create** captured the scheduled-task payload execution:

| Field | Observed value |
| --- | --- |
| Image | `C:\Windows\System32\cmd.exe` |
| CommandLine | `"C:\Windows\System32\cmd.exe" /c "C:\Users\Public\SOC-LAB-T1053.cmd"` |
| ParentImage | `C:\Windows\System32\svchost.exe` |
| User | `Windows11off\faris` |
| ProcessId | `7032` in the captured run |

The `svchost.exe` parent is consistent with Task Scheduler service execution context and strengthens the task-execution correlation.

## Alert configuration

The saved Splunk alert is:

`SOC-004 - Suspicious Scheduled Task Creation`

| Setting | Captured value |
| --- | --- |
| Type | Scheduled |
| Cron | `*/5 * * * *` |
| Search window | Last 5 minutes |
| Trigger condition | Number of Results > 0 |
| Trigger mode | Once |
| Action | Add to Triggered Alerts |
| Severity | Medium |
| Expiration | 24 hours |
| Status | Enabled |

## Scheduled firing validation

A fresh validation task named `\SOC-LAB-T1053-ALERT` was created after the alert was enabled.

The alert page displayed a **Trigger History** entry at:

```text
2026-10-09 13:00:01 UTC
```

Selecting **View Results** returned **1 event** in the scheduled job and showed:

- User: `faris`
- TaskName: `\SOC-LAB-T1053-ALERT`
- Event source: Windows Security 4698

This confirms the path from task creation through Security logging, Splunk ingestion, scheduled detection, and alert firing.

## Tuning considerations

Event 4698 is high-value but scheduled tasks are also common in legitimate software. Production tuning should consider:

- task path and naming conventions,
- executable path,
- encoded or script-based arguments,
- writable/user-profile locations,
- unusual creator accounts,
- parent process and correlated Sysmon activity,
- known software deployment and maintenance tooling.

The rule should not treat all scheduled-task creation as malicious.

[Simulation](../attack-simulations/scheduled-task.md) · [Investigation](../investigations/incident-005-scheduled-task.md) · [MITRE T1053.005](https://attack.mitre.org/techniques/T1053/005/)
