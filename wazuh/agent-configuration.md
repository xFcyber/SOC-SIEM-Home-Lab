# Windows agent collection

Record the following from the real deployment:

| Field | Value to complete |
| --- | --- |
| Manager IP | Pending |
| Agent name / ID | Pending |
| Agent version | Pending |
| Connection state and timestamp | Pending |
| Configured Windows event channels | Pending |
| Sysmon channel collected by Wazuh | Not yet confirmed |

Check the active agent configuration rather than copying an entire `ossec.conf` into the public repository. Document the manager address and event channel names in sanitized notes.

For a sample event, retain timestamp, channel/provider, event ID and agent identifier. For an alert, also retain the actual rule ID, level and message.

Never publish agent enrollment secrets, credentials or keys.

