# Suspicious PowerShell encoded execution

**Status:** Manual detection confirmed and scheduled alert firing confirmed.

## Detection goal

Identify PowerShell process creation where the command line combines an encoded command with a hidden window. The data source is Sysmon Event ID **1 — Process Create** forwarded to Splunk.

MITRE ATT&CK mapping: **T1059.001 — PowerShell**.

## Query

```spl
index=main
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>1</EventID>"
("powershell.exe" OR "pwsh.exe")
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>[^<]*)</Data>"
| rex field=_raw "<Data Name='ProcessGuid'>(?<ProcessGuid>[^<]*)</Data>"
| where match(CommandLine,"(?i)(^|\\s)-(enc|encodedcommand)\\s+")
    AND match(CommandLine,"(?i)-windowstyle\\s+hidden")
| table _time User Image CommandLine ParentImage ProcessId ProcessGuid
| sort - _time
```

Repository SPL: [suspicious-powershell.spl](suspicious-powershell.spl).

## Detection tuning

The initial broad search for PowerShell activity returned multiple events, including a legitimate PowerShell command launched in the Wazuh agent context. This demonstrated why a rule such as “any PowerShell execution” or “PowerShell with `-NoProfile`” would be too noisy.

The analytic was tuned to require both:

1. `-EncodedCommand` or the `-enc` alias, and
2. `-WindowStyle Hidden`.

The tuned manual search returned one suspicious lab event instead of the unrelated Wazuh activity.

This is an educational rule, not a universal production rule. Legitimate administration tools can still use these flags, while malicious scripts can avoid them entirely.

## Alert configuration

The saved Splunk alert is:

`SOC-003 - Suspicious PowerShell Encoded Execution`

| Setting | Value |
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

A fresh controlled PowerShell execution was generated after the alert was enabled. The alert page then displayed a row under **Trigger History** with trigger time **2026-10-09 09:20:03 UTC**.

Opening **View Results** returned exactly one scheduled-search result in the interval **09:15:00–09:20:00** as displayed by Splunk. The result contained:

- `powershell.exe`
- `-NoProfile`
- `-WindowStyle Hidden`
- `-EncodedCommand`

This confirms the full path from Sysmon ingestion through scheduled Splunk detection and alert firing.

## Limitations

- Encoded PowerShell is not automatically malicious.
- Attackers may use PowerShell without these flags.
- Other interpreters such as `cmd.exe`, `wscript.exe`, `cscript.exe`, or `mshta.exe` are outside this rule.
- Production deployment should add allowlists, parent-process context, code-signing context, user/host baselines and threat intelligence as appropriate.

[Simulation](../attack-simulations/powershell.md) · [Investigation](../investigations/incident-004-suspicious-powershell.md) · [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)
