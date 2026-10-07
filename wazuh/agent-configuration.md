# Windows agent collection

## Screenshot-supported inventory

| Field | Observed value |
| --- | --- |
| Agent name / ID | windows-lab / 001 |
| Endpoint host name | WINDOWS11OFF |
| Status | Active at screenshot time |
| Registration | Oct 3, 2026 @ 10:02:51.000, dashboard display |
| Last keep alive | Oct 5, 2026 @ 11:17:05.000, dashboard display |
| Wazuh dashboard URL | 192.168.10.10 |
| Actual agent-configured manager endpoint | Not captured |
| Agent version | Not captured |
| Event channels / Sysmon collection | Not established by this screenshot |

![Active Wazuh endpoint](../screenshots/wazuh-agent-active.png)

The screenshot establishes manager/dashboard recognition of the endpoint at the captured time. Summary charts do not establish individual event content, a specific rule, Sysmon collection or present-day connection state.

Next evidence: sanitized agent configuration and a matching individual event or alert. Preserve actual timestamps and rule IDs; do not invent missing values.

Do not publish enrollment keys or credentials.
