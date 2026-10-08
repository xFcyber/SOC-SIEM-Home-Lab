# Scheduled port scan alert

**Status: revised schedule proposal; an existing alert definition is shown below, but successful firing remains unverified.**

![Existing enabled alert with no displayed fired events](../screenshots/splunk-alert-enabled-no-fires.png)

The captured Possible Port Scan Detected alert is enabled, scheduled and configured to add triggered records when results exceed zero. It explicitly displays no fired events. Its actual cron expression, window and query are not visible; the settings below are proposed for the revised analytic.

The [case 002 manual replay](../investigations/incident-002-controlled-port-scan.md) confirms the core extraction, grouping and threshold for an authorized eight-port scan. Scheduled firing remains pending. Use the validated aggregation logic or the [generic port scan SPL](../detections/pfsense-ipv4-port-scan.spl) for the scheduled definition. Remove fixed epoch earliest/latest modifiers used for replay, then configure the relative alert window below.

| Setting | Proposed value |
| --- | --- |
| Name | SOC Lab — IPv4 TCP Port Scan Candidate |
| Type | Scheduled |
| Cron | `*/5 * * * *` |
| Earliest | `-6m@m` |
| Latest | `-1m@m` |
| Trigger | Number of results greater than 0 |
| Action | Add to Triggered Alerts |
| Initial throttling | Off during validation |

This evaluates a five-minute window delayed by one minute to allow ingestion. Adjacent on-time runs have adjacent windows. Measure actual delay; late arrivals or missed jobs can still cause gaps. Splunk Enterprise scheduling uses the configured search-head timezone.

The SPL aggregates over the selected search window. Do not add a separate five-minute `bin` without reviewing alignment.

## Validate

1. Confirm the search returns correct IPs and ports over a known scan window.
2. Create the scheduled alert in Search and Reporting.
3. Generate the controlled test in the attacker segment and record its timestamps.
4. Inspect the scheduled search job and Triggered Alerts.
5. Attach the schedule settings, a result and its underlying raw events.

A saved search definition does not demonstrate successful scheduled execution. Availability also depends on the installed Splunk edition/license and permissions.

Once verified, tune thresholds and optionally suppress repeated candidates by source/destination. Document any suppression so repeated testing does not appear to fail silently.

Reference: [Splunk scheduling guidance](https://help.splunk.com/en/splunk-cloud-platform/alert-and-respond/alerting-manual/10.3.2512/create-alerts/alert-scheduling-tips).



## Windows brute-force alert

**Status:** Saved, enabled and manually validated; scheduled firing has not yet been captured.

The 2026-10-08 failed-logon exercise produced five Windows Event ID 4625 records from Kali `192.168.20.20` against the lab account `SOC-Test`. The grouped search returned one candidate with five failures, `Workstation=KALI` and `LogonType=3`.

The saved Splunk alert is:

`SOC-002 - Brute Force Failed Logon Detection`

| Setting | Captured value |
| --- | --- |
| Type | Scheduled |
| Cron | `*/5 * * * *` |
| Search window | Last 5 minutes |
| Trigger | Number of results greater than 0 |
| Action | Add to Triggered Alerts |
| Severity | Medium |
| Status | Enabled |

Use the [Windows brute-force analytic](../detections/windows-brute-force-detection.md) and [SPL file](../detections/windows-brute-force.spl). The [case 003 investigation](../investigations/incident-003-brute-force.md) documents endpoint and pfSense correlation plus the negative Event ID 4624 follow-up.

A saved and enabled alert does not prove a scheduled trigger occurred. Capture a fresh run in Triggered Alerts before marking scheduled firing as validated.
