# Wazuh setup and validation

The lab uses Wazuh on a separate Ubuntu Server and a Windows agent.

**Previously observed:** manager installed and Windows agent service running. **Still needed for this repository:** actual manager IP, connected-agent evidence and a collected event or alert.

1. Record the manager's actual lab IP and installed version.
2. Check the Windows agent's configured manager address.
3. Confirm the agent is connected from the manager/dashboard.
4. Generate a harmless Windows event and look for it in the relevant Wazuh view.
5. Record the event timestamp, agent name and rule ID if an alert exists.

Collection and alerting are separate: not every collected event matches an alert rule. A dashboard count is a summary; inspect the underlying event/alert details for evidence.

Do not claim a Wazuh detection of the port scan until evidence supports it. The first case uses pfSense logs in Splunk.

