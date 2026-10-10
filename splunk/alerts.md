# Scheduled port scan alert

**Status:** Relative-window correction and fresh scheduled firing confirmed on 2026-10-10. Trigger History and scheduler results match the new eight-port scan; the unchanged raw CSV reproduces the scheduled aggregation. Exact cron/dispatch settings and native Nmap output remain pending.

## Earlier saved definition

![Earlier enabled alert with no displayed fired events](../screenshots/splunk-alert-enabled-no-fires.png)

The earlier **Possible Port Scan Detected** capture shows an enabled scheduled alert configured to add triggered records when results exceed zero. It displays no fired events at that capture time. Its actual cron expression, window and query are not visible.

## Observed scheduled firing — 2026-10-09

![SOC Lab IPv4 TCP port-scan scheduled Trigger History](../screenshots/splunk-port-scan-alert-triggered-20261009-case002.png)

The newly captured saved alert is **SOC Lab - IPv4 TCP Port Scan**. The screenshot does not establish whether it is a rename of the earlier definition or a separate saved search.

| Setting | Captured value |
| --- | --- |
| Name | SOC Lab - IPv4 TCP Port Scan |
| Enabled | Yes |
| Type | Scheduled; Cron Schedule |
| Trigger | Number of Results greater than 0 |
| Action | Add to Triggered Alerts |
| App / owner / permissions | search / off / Private |
| Latest visible firing | 2026-10-09 18:30:02 UTC (21:30:02 Asia/Riyadh) |
| Exact cron expression | Not visible |

Multiple preceding Trigger History rows recur at approximately five-minute intervals. The following scheduler result identifies the inspected firing's traffic and effective window.

## Scheduled job reveals historical replay bounds

![Scheduled job repeats the October 7 eight-port result](../screenshots/splunk-port-scan-scheduled-replay-20261009-case002.png)

The **View Results** URL contains a scheduler job identifier with `at_1791570600`, corresponding to **2026-10-09 18:30:00 UTC**. The completed search returns **8 events / Statistics (1)** over **2026-10-07 12:52–12:57**, with source **192.168.20.20**, destination **192.168.10.100**, **8 distinct ports / 8 logged events** and **pass**.

Its first line is:

```spl
index=pfSense "filterlog" earliest=1791377520 latest=1791377820
```

Those epochs decode to **2026-10-07 12:52:00–12:57:00 UTC**. The core query and output match the [case 002 historical replay](../investigations/incident-002-replay.spl). The inspected scheduled job therefore re-evaluates the old controlled scan. Fixed historical bounds allow unchanged old records to satisfy the alert repeatedly; the other firing rows have not been individually inspected.

Inline time bounds take precedence over the time-range picker. The old completed-job interval confirms their effect in this job. A picker-only change is insufficient while those epochs remain in the saved SPL. [Splunk time-modifier reference](https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/specify-time-ranges/specify-time-modifiers-in-your-search).

This confirms scheduled **historical replay**, with a configuration issue for ongoing monitoring. It does not establish a new scan or validation of a live relative window.

## Relative-window correction verified — 2026-10-10

The fresh [Nmap capture](../screenshots/kali-port-scan-retest-20261010-case002.png) records the completed scan at **11:28:25 +03:00 (08:28:25 UTC)**. The updated alert overview and matching scheduler job provide the fresh validation:

![Fresh port-scan Trigger History](../screenshots/splunk-port-scan-alert-triggered-20261010-case002.png)

![Fresh relative-window scheduled result](../screenshots/splunk-port-scan-scheduled-results-20261010-case002.png)

| Configuration / result | Observed value |
| --- | --- |
| Alert name | SOC Lab - IPv4 TCP Port Scan |
| Enabled / type | Yes / Scheduled; Cron Schedule |
| Trigger / action | Results > 0 / Add to Triggered Alerts |
| Modified field, as displayed | Oct 10, 2026 8:20:28 AM; no explicit offset |
| Fresh trigger | 2026-10-10 08:30:02 UTC (11:30:02 Asia/Riyadh) |
| Scheduler launch reference | `at_1791621000` = 2026-10-10 08:30:00 UTC |
| Executed query earliest / latest | `-6m@m` / `-1m@m` |
| Completed-job displayed window | 2026-10-10 08:24:00–08:29:00 |
| Event / grouped-result count | 8 / 1 |
| Source → destination | 192.168.20.20 → 192.168.10.100 |
| Unique ports / logged events | 8 / 8 |
| Destination ports | 22, 80, 135, 139, 443, 445, 3389, 5985 |
| Firewall actions | pass |
| Exact cron, dispatch-time fields and suppression | Not visible |

The executed [scheduled SPL](../detections/pfsense-ipv4-port-scan-scheduled.spl) begins with:

```spl
index=pfSense "filterlog" earliest=-6m@m latest=-1m@m
```

The corrected job evaluates a five-minute moving window delayed by one minute, and its window contains the fresh scan time. Its indexed source/target pair and port set match the controlled run. This verifies the applied correction and fresh scheduled detection; the earlier fixed-window job remains documented as historical replay.

The complete visible core query is transcribed without adding optional columns. The [generic extended SPL](../detections/pfsense-ipv4-port-scan.spl) is retained separately. No fixed replay epochs are included in the live scheduled variant.

## Schedule details still needing capture

| Setting | Evidence status |
| --- | --- |
| Relative earliest / latest in executed SPL | Confirmed: `-6m@m` / `-1m@m` |
| Scheduled type | Confirmed: Cron Schedule |
| Exact cron expression | Not captured; `*/5 * * * *` remains the intended configuration |
| Dispatch-time fields / suppression | Not captured |
| Persistent route-recovery configuration | Not captured |

The approximate five-minute cadence in older history rows is not substituted for an actual cron-setting screenshot. Align and capture the saved schedule/time settings when available. Late-arrival behavior, missed-job coverage and ingestion delay have not been measured by this one successful test.

## Raw-record reconciliation

The [original raw firewall CSV](../investigations/evidence/soc-port-scan-events-20261010.csv) contains **8 distinct inbound IPv4 TCP SYN records**, with `_time=2026-10-10T08:28:32.000+0000`, inside the **08:24–08:29 UTC** job window. Its source/target pair, exact eight-port set and **pass** action independently reproduce **1 grouped result / 8 distinct ports / 8 logged events**. The export preserves host **192.168.10.1**, source **udp:5514**, sourcetype **syslog**, interface **em2** and source port **37074**. [Case 002 field validation, checksum and timestamp limits](../investigations/incident-002-controlled-port-scan.md#evidence-10--original-raw-firewall-csv-reconciled--2026-10-10).

## Remaining evidence

1. Upload the native `soc-port-scan-20261010.txt` output.
2. Capture exact cron/dispatch settings and any suppression configuration.

Scheduled firing and matching results are complete for this controlled case. Threshold tuning and any future suppression should be documented after reviewing repeated candidates.

[Case 002 complete validation](../investigations/incident-002-controlled-port-scan.md) · [Splunk scheduling guidance](https://help.splunk.com/en/splunk-cloud-platform/alert-and-respond/alerting-manual/10.3.2512/create-alerts/alert-scheduling-tips).

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

The [original raw-event CSV](../investigations/evidence/soc-002-4625-events-20261009.csv) contains all **5 distinct Security 4625 records** from this scheduled-job window, preserving the Windows XML and explicit UTC timestamps. [Field validation and checksum](../investigations/incident-003-brute-force.md#evidence-8--raw-windows-security-csv-export--2026-10-09).


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
