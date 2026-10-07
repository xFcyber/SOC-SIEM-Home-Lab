# Sysmon endpoint telemetry

Sysmon was installed on Windows 11 with a configuration file. Event ID 1 was previously observed.

Read-only PowerShell check:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
    Select-Object TimeCreated, Id, ProviderName, Message
```

## Events relevant to later exercises

| Event ID | Telemetry | Lab evidence |
| --- | --- | --- |
| 1 | Process creation | Previously observed; screenshot pending |
| 3 | Network connections | Collection must be checked |
| 7 | Module/image loading | Collection must be checked |
| 10 | Process access | Collection must be checked |
| 11 | File creation | Collection must be checked |
| 22 | DNS queries | Collection must be checked |

Events 3 and 7 are disabled by default; event selection depends on configuration. Sysmon records activity and does not independently classify it as malicious.

A local event proves local logging. Find the corresponding event in Splunk to prove the collection path.

Reference: [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

