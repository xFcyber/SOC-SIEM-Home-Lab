# Case 005 — Scheduled Task persistence

**Splunk alert ID:** SOC-004  
**Status:** Task creation, endpoint execution, Security event detection and scheduled alert firing confirmed.

## Executive summary

On 2026-10-09, the Windows 11 lab endpoint created an authorized test Scheduled Task named **SOC-LAB-T1053**. Windows Security auditing recorded Event ID **4698 — A scheduled task was created**. Sysmon independently recorded process creation associated with both `schtasks.exe` activity and the task-launched `cmd.exe` payload.

A Splunk alert named **SOC-004 - Suspicious Scheduled Task Creation** was created with a five-minute schedule. A fresh task named **SOC-LAB-T1053-ALERT** then generated a new 4698 event. The alert fired successfully, and **View Results** returned one matching task-creation event.

**Verdict:** True positive for the tested Scheduled Task persistence behavior.  
**Context:** Authorized lab simulation.  
**Severity:** Medium.  
**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task.

## Evidence 1 — Audit policy

The required Windows audit subcategory was initially:

```text
Other Object Access Events    No Auditing
```

It was enabled for success and failure auditing, after which the policy displayed:

```text
Other Object Access Events    Success and Failure
```

This change enabled Security Event ID 4698 visibility for the exercise.

## Evidence 2 — Windows Security Event ID 4698

Splunk returned an XML-rendered Security event containing:

- Event ID: **4698**
- Task name: `\SOC-LAB-T1053`
- User: `faris`
- Task XML containing the configured action

This directly confirms creation of the scheduled task.

## Evidence 3 — Sysmon process creation

Sysmon Event ID **1** recorded `schtasks.exe` for the task creation operation.

After troubleshooting the task action, Sysmon also captured the task-launched command process:

| Field | Observed value |
| --- | --- |
| User | `Windows11off\faris` |
| Image | `C:\Windows\System32\cmd.exe` |
| CommandLine | `"C:\Windows\System32\cmd.exe" /c "C:\Users\Public\SOC-LAB-T1053.cmd"` |
| ParentImage | `C:\Windows\System32\svchost.exe` |
| ProcessId | `7032` |

This provides execution evidence separate from the Security task-creation event.

## Troubleshooting note

The first task action attempted to embed output redirection directly in the `schtasks.exe /TR` argument. The task was created but the expected marker file was not produced.

The task was then rebuilt around a dedicated `.cmd` file and explicit `cmd.exe /c` execution. This resulted in the expected process telemetry.

Keeping this failed first attempt in the case is useful because it distinguishes:

- **task creation succeeded**, from
- **task payload execution succeeded**.

A SOC investigation should not assume the second merely from the first.

## Evidence 4 — Detection result

The Security analytic extracted:

- `User=faris`
- `TaskName=\SOC-LAB-T1053`

and returned one result for the controlled creation event.

The scheduled alert configuration used:

```text
SOC-004 - Suspicious Scheduled Task Creation
Schedule: */5 * * * *
Window: Last 5 minutes
Trigger: Number of Results > 0
Action: Add to Triggered Alerts
Severity: Medium
```

## Evidence 5 — Scheduled alert firing

A second validation task was created:

```text
\SOC-LAB-T1053-ALERT
```

The SOC-004 alert then displayed a Trigger History row at:

```text
2026-10-09 13:00:01 UTC
```

**View Results** returned one event with:

```text
User     : faris
TaskName : \SOC-LAB-T1053-ALERT
```

The scheduled detection therefore completed end-to-end:

```text
Task creation
     |
     v
Windows Security 4698
     |
     +---- Sysmon Event ID 1 process correlation
     |
     v
Splunk security_logs
     |
     v
SOC-004 scheduled analytic
     |
     v
Trigger History
     |
     v
View Results: 1 matching event
```

## Analyst conclusion

This is a **true positive for the persistence behavior being tested**, with authorized-lab context.

There is no evidence in this exercise of malware, credential theft, lateral movement, or an external attacker. The purpose was to validate telemetry and detection for Scheduled Task creation and execution.

## Real-SOC response considerations

For an unexpected production 4698 event:

1. Review the creator account and host.
2. Inspect the full TaskContent XML and command arguments.
3. Determine whether the executable resides in a user-writable or temporary path.
4. Correlate with Sysmon process creation, file creation, registry and network events.
5. Check for related 4699/4702 events and additional tasks.
6. Validate whether the task belongs to software deployment, maintenance or endpoint tooling.
7. Disable/remove the task and contain the endpoint when malicious persistence is confirmed.
8. Preserve task XML and process telemetry for escalation.

[Simulation](../attack-simulations/scheduled-task.md) · [Detection](../detections/scheduled-task-detection.md) · [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)
