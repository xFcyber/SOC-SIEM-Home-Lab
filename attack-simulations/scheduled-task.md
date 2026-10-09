# Controlled scheduled-task persistence simulation

**Exercise date:** 2026-10-09  
**Scope:** Authorized SOC home lab only.

This exercise simulated Windows persistence using a Scheduled Task and validated detection with Windows Security auditing, Sysmon, and Splunk.

## Preparation

Windows auditing for **Other Object Access Events** was initially disabled. It was enabled with:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

A follow-up check showed:

```text
Other Object Access Events    Success and Failure
```

## Controlled task creation

The lab created a scheduled task named:

```text
SOC-LAB-T1053
```

The task was configured to run at user logon and execute a harmless command file in `C:\Users\Public`.

During troubleshooting, the first inline command version did not create the expected marker file. The task was rebuilt to launch `cmd.exe /c` against a dedicated `.cmd` file. This produced observable execution telemetry and is documented as part of the investigation rather than hidden from the case history.

The task execution path ultimately observed by Sysmon was:

```text
C:\Windows\System32\cmd.exe /c "C:\Users\Public\SOC-LAB-T1053.cmd"
```

with parent:

```text
C:\Windows\System32\svchost.exe
```

## Detection validation task

After creating the Splunk alert, a second task named:

```text
SOC-LAB-T1053-ALERT
```

was created to generate a fresh Windows Security Event ID 4698 inside the alert's five-minute search window.

The scheduled alert fired successfully and the saved-search results returned the new task.

## ATT&CK mapping

**T1053.005 — Scheduled Task/Job: Scheduled Task**

The exercise demonstrates task creation and task-launched command execution. It does not claim malicious persistence outside the authorized lab.

[Detection analytic](../detections/scheduled-task-detection.md) · [Investigation](../investigations/incident-005-scheduled-task.md)
