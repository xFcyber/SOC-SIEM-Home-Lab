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

**Status:** Saved, enabled, manually validated and scheduled firing confirmed on 2026-10-09.

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

A fresh five-attempt SMB retest caused **Trigger History** to record **2026-10-09 17:50:01 UTC (20:50:01 Asia/Riyadh)**. Its **View Results** scheduler job displays **5 events / 1 grouped result** for **192.168.20.20**, **SOC-Test**, **KALI** and **LogonType=3**, in the **17:45–17:50** window shown by Splunk. The executed query uses five-minute buckets and preserves original first/last event timestamps.

![SOC-002 scheduled firing](../screenshots/splunk-brute-force-alert-triggered-20261009-case003.png)

![SOC-002 scheduled results](../screenshots/splunk-brute-force-scheduled-results-20261009-case003.png)

The fresh-test successful-logon search returns **0 matching Event ID 4624 records** from **192.168.20.20** for **17:45:00–18:04:33 as displayed by Splunk**, covering the failed batch. [Original screenshot](../screenshots/splunk-successful-logon-check-retest-20261009-case003.png). Full-window coverage of the original 2026-10-08 exercise remains pending.


## Suspicious PowerShell encoded execution alert

**Status:** Saved, enabled and scheduled firing confirmed.

The saved alert is:

`SOC-003 - Suspicious PowerShell Encoded Execution`

| Setting | Captured value |
| --- | --- |
| Type | Scheduled |
| Cron | `*/5 * * * *` |
| Search window | Last 5 minutes |
| Trigger | Number of results greater than 0 |
| Trigger mode | Once |
| Action | Add to Triggered Alerts |
| Severity | Medium |
| Expiration | 24 hours |
| Status | Enabled |

After a fresh controlled test, the alert page displayed a **Trigger History** row at **2026-10-09 09:20:03 UTC**. Opening **View Results** returned **1 event** from the scheduled window and showed the expected PowerShell command line containing `-NoProfile`, `-WindowStyle Hidden` and `-EncodedCommand`.

This is the first alert in the repository with both saved configuration and a captured scheduled firing.

[Detection](../detections/suspicious-powershell-detection.md) · [Case 004](../investigations/incident-004-suspicious-powershell.md)


## Suspicious Scheduled Task creation alert

**Status:** Saved, enabled and scheduled firing confirmed.

The saved alert is:

`SOC-004 - Suspicious Scheduled Task Creation`

| Setting | Captured value |
| --- | --- |
| Type | Scheduled |
| Cron | `*/5 * * * *` |
| Search window | Last 5 minutes |
| Trigger | Number of results greater than 0 |
| Trigger mode | Once |
| Action | Add to Triggered Alerts |
| Severity | Medium |
| Expiration | 24 hours |
| Status | Enabled |

A fresh validation task named `\SOC-LAB-T1053-ALERT` was created after the alert was enabled. Trigger History recorded a firing at **2026-10-09 13:00:01 UTC**. Opening **View Results** returned **1 event** and showed `User=faris` and `TaskName=\SOC-LAB-T1053-ALERT`.

The lab validation query included a task-name fallback for the controlled `SOC-LAB` task. The repository's generic analytic removes that lab-only dependency and focuses on suspicious task content.

[Detection](../detections/scheduled-task-detection.md) · [Case 005](../investigations/incident-005-scheduled-task.md)


## Possible ransomware mass file activity alert

**Status:** Saved, enabled and scheduled firing confirmed.

The saved alert is:

`SOC-005 - Possible Ransomware Mass File Activity`

| Setting | Captured value |
| --- | --- |
| Type | Scheduled |
| Cron | `*/5 * * * *` |
| Search window | Last 5 minutes |
| Trigger | Number of results greater than 0 |
| Trigger mode | Once |
| Action | Add to Triggered Alerts |
| Severity | High |
| Expiration | 24 hours |
| Status | Enabled |

The analytic uses Windows Security Event ID **4663** scoped to the dedicated ransomware test directory, groups events into one-minute windows and requires at least **10 distinct filenames** with `.encrypted` or `.locked` extensions.

The first manual validation returned **20 AccessEvents / 20 UniqueFiles** for PowerShell. After the alert was enabled, a fresh 15-file batch was generated. Trigger History recorded a firing at **2026-10-09 14:20:01 UTC**, and **View Results** returned **15 AccessEvents / 15 UniqueFiles**, `User=faris` and the PowerShell process path.

The lab maps this behavior to **MITRE ATT&CK T1486 — Data Encrypted for Impact**, while explicitly noting that no real file encryption was performed.

[Detection](../detections/ransomware-mass-file-activity.md) · [Case 006](../investigations/incident-006-ransomware-like-file-activity.md)
