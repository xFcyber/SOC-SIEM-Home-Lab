# Wazuh setup and validation

The lab uses Wazuh on a separate Ubuntu Server and a Windows agent.

**Screenshot evidence:** windows-lab (001) active in the Wazuh endpoint page, last keep alive Oct 5, 2026 @ 11:17:05.000. Dashboard URL: 192.168.10.10. The agent-configured manager endpoint and individual event details still need confirmation.

![Active Windows agent](../screenshots/wazuh-agent-active.png)

1. Record the manager's actual lab IP and installed version.
2. Check the Windows agent's configured manager address.
3. Confirm the agent is connected from the manager/dashboard.
4. Generate a harmless Windows event and look for it in the relevant Wazuh view.
5. Record the event timestamp, agent name and rule ID if an alert exists.

Collection and alerting are separate: not every collected event matches an alert rule. A dashboard count is a summary; inspect the underlying event/alert details for evidence.

Do not claim a Wazuh detection of the port scan until evidence supports it. The first case uses pfSense logs in Splunk.

