# Splunk Universal Forwarder

The Windows forwarder previously reported an active connection to `192.168.10.20:9997`.

## Read-only checks

Run from an elevated PowerShell window if needed:

```powershell
Get-Service SplunkForwarder
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
Test-NetConnection 192.168.10.20 -Port 9997
```

Adjust the installation path if different. Do not include authentication output or secrets in screenshots.

## Sysmon input example

[inputs.conf.example](inputs.conf.example) describes the previously used Sysmon channel and `main` index. Review the active configuration and merged settings before applying any example.

Security, System and Application collection require their own enabled inputs and validation; this repository does not mark them collected.

## End-to-end check

Find a specific local Sysmon event in Splunk and compare host, event ID, timestamp and event content. An active forwarding connection alone is not proof that the desired channel is being indexed.

