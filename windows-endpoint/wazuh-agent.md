# Windows Wazuh agent

The Windows service `WazuhSvc` was previously confirmed running.

```powershell
Get-Service WazuhSvc
```

The attached [dashboard screenshot](../screenshots/wazuh-agent-active.png) shows windows-lab (001) active with last keep alive Oct 5, 2026 @ 11:17:05.000. Check the configured manager address separately and collect an individual event detail. The screenshot is a historical observation, not a current live check.

Complete the [collection inventory](../wazuh/agent-configuration.md). Do not infer that Sysmon is collected simply because WazuhSvc is running.

Use a sanitized event or alert to demonstrate the pipeline. Leave any unobserved rule IDs or alert levels blank.

