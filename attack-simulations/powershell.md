# Controlled suspicious PowerShell execution

**Exercise date:** 2026-10-09  
**Scope:** Authorized SOC home lab only.

This exercise generated a safe PowerShell process with command-line characteristics that are commonly suspicious in enterprise monitoring: `-NoProfile`, `-WindowStyle Hidden`, and `-EncodedCommand`.

The encoded payload was intentionally harmless. It created a text file in the current user's temporary directory and wrote a short SOC lab marker string.

## Executed lab behavior

```powershell
$cmd = 'New-Item -Path "$env:TEMP\SOC-LAB-PS.txt" -ItemType File -Force | Out-Null; Set-Content -Path "$env:TEMP\SOC-LAB-PS.txt" -Value "SOC-LAB T1059.001 test"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $enc
```

The endpoint later confirmed the marker file contents with:

```powershell
Get-Content "$env:TEMP\SOC-LAB-PS.txt"
```

Observed output:

```text
SOC-LAB T1059.001 test
```

## Telemetry

Sysmon Event ID **1 — Process Create** captured the PowerShell execution in Splunk. The event showed:

- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Command-line indicators: `-NoProfile`, `-WindowStyle Hidden`, `-EncodedCommand`
- Source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- Sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

A broad PowerShell search initially also returned legitimate PowerShell activity related to Wazuh. The detection was therefore tuned to require the suspicious encoded/hidden-window behavior rather than treating every PowerShell process as malicious.

## Scope and safety

No malware, persistence mechanism, credential theft, exploitation, payload download, or external target was used. The exercise was limited to the Windows 11 lab VM and a harmless local file.

[Detection analytic](../detections/suspicious-powershell-detection.md) · [Investigation](../investigations/incident-004-suspicious-powershell.md)
