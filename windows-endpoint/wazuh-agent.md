# Windows Wazuh agent

The Windows service `WazuhSvc` was previously confirmed running.

```powershell
Get-Service WazuhSvc
```

Check the configured manager address against the current Wazuh server IP, then verify a connected agent from the manager/dashboard. Record both the service check and manager-side confirmation.

Complete the [collection inventory](../wazuh/agent-configuration.md). Do not infer that Sysmon is collected simply because WazuhSvc is running.

Use a sanitized event or alert to demonstrate the pipeline. Leave any unobserved rule IDs or alert levels blank.

