# Case 003 — Controlled SMB brute-force / failed-logon investigation

**Status:** Controlled attack, endpoint evidence, firewall correlation and manual detection confirmed. Splunk alert saved and enabled; scheduled firing remains unconfirmed.

## Executive summary

On 2026-10-08, Kali Linux at **192.168.20.20** generated five controlled failed SMB authentication attempts against the Windows 11 lab target **192.168.10.100** using the test account **SOC-Test**. Kali returned `NT_STATUS_LOGON_FAILURE`.

Windows Security auditing generated Event ID **4625** records. A Splunk analytic grouped five failures for the same source IP and target account, with **Workstation=KALI** and **LogonType=3 (Network)**. pfSense independently recorded TCP traffic from the same source to the same target on destination port **445**. A follow-up Splunk search found **0 Event ID 4624 successful logons from 192.168.20.20** during the checked one-hour window.

**Verdict:** True positive for the controlled failed-authentication / brute-force behavior.  
**Disposition:** Authorized lab activity; unsuccessful authentication attempt.  
**Severity:** Medium for the lab scenario.  
**Observed impact:** No successful account compromise observed.  
**MITRE ATT&CK:** T1110 — Brute Force.

## Visual evidence

![SOC-002 brute-force detection evidence](../screenshots/soc-002/evidence.png)

The PNG above is cropped from the captured lab screenshot so the key Splunk result remains readable directly inside the investigation.

## Scope

| Role | Observed value |
| --- | --- |
| Source | Kali Linux, 192.168.20.20 |
| Target | Windows 11, 192.168.10.100 |
| Target account | SOC-Test |
| Service | SMB / TCP 445 |
| Firewall | pfSense |
| SIEM | Splunk Enterprise |
| Windows log index | security_logs |
| Windows event | 4625 |
| Successful-logon check | 4624 |
| Detection threshold | 5 failures in 5 minutes |

The correct password for the test account is intentionally excluded from the repository.

## Evidence 1 — Controlled authentication failures

The exercise used five incorrect passwords against the dedicated lab account:

```bash
for pass in WrongPass1 WrongPass2 WrongPass3 WrongPass4 WrongPass5; do
    echo "Trying password: $pass"
    smbclient -L //192.168.10.100 -U "SOC-Test%$pass" -m SMB3
    sleep 2
done
```

The captured output returned `NT_STATUS_LOGON_FAILURE` for each attempted password. TCP 445 had been confirmed reachable before the run.

Windows account policy showed a lockout threshold of 10 attempts, so the test was limited to five.

## Evidence 2 — Windows Security Event ID 4625

Windows itself confirmed Event ID 4625 records after the test. Splunk also returned events when searching the XML-rendered Security channel.

A focused search for the controlled source, account and event returned the five relevant records:

```spl
index=security_logs "4625" "SOC-Test" "192.168.20.20"
```

The XML records exposed values including the target account, source address and network logon type.

## Evidence 3 — Detection aggregation

The validated analytic returned:

| Field | Result |
| --- | --- |
| Source IP | 192.168.20.20 |
| Target user | SOC-Test |
| Failed count | 5 |
| Workstation | KALI |
| Logon type | 3 |
| First seen | 2026-10-08 12:48:03.986 as displayed by Splunk |
| Last seen | 2026-10-08 12:48:50.113 as displayed by Splunk |

The executed validation preserved original event time before five-minute bucketing so first/last event timestamps remained visible.

See [the analytic](../detections/windows-brute-force-detection.md).

## Evidence 4 — Successful-login check

The investigation searched Event ID 4624 for the Kali address:

```spl
index=security_logs "<EventID>4624</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpPort'>(?<IpPort>[^<]*)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]*)</Data>"
| rex field=_raw "<Data Name='WorkstationName'>(?<WorkstationName>[^<]*)</Data>"
| search IpAddress="192.168.20.20"
| table _time TargetUserName IpAddress IpPort LogonType WorkstationName
| sort - _time
```

The captured search returned **0 events** for **2026-10-08 12:49:00–13:49:06**, as displayed by Splunk. This window starts after the failed-logon batch (**12:48:03.986–12:48:50.113**), so it is a follow-up check rather than complete coverage of the original attempt period. No successful logon was observed in the checked window. A new fixed-window search spanning before, during and after the attempts is still needed to cover that entire period; this result does not establish absence outside the searched window or through another source address.

## Evidence 5 — pfSense network correlation

pfSense filterlog independently recorded traffic from Kali to the Windows SMB service. A parsed Splunk view showed multiple inbound, passed TCP records with:

- `src_ip=192.168.20.20`
- `dst_ip=192.168.10.100`
- `dst_port=445`
- `protocol=tcp`
- `action=pass`
- `direction=in`

The review displayed seven firewall records around the exercise period. Firewall connection/log counts are not expected to equal Windows authentication-event counts one-for-one.

The parsing query used for the evidence view was:

```spl
index=pfsense "192.168.20.20" "192.168.10.100" "445"
| rex field=_raw "filterlog\[\d+\]:\s+(?<pfdata>.*)"
| eval f=split(pfdata,",")
| eval interface=mvindex(f,4)
| eval action=mvindex(f,6)
| eval direction=mvindex(f,7)
| eval protocol=mvindex(f,16)
| eval src_ip=mvindex(f,18)
| eval dst_ip=mvindex(f,19)
| eval src_port=mvindex(f,20)
| eval dst_port=mvindex(f,21)
| search src_ip="192.168.20.20" dst_ip="192.168.10.100" dst_port="445"
| table _time action direction protocol src_ip src_port dst_ip dst_port
| sort - _time
```

## Alert configuration

The saved Splunk alert is named:

`SOC-002 - Brute Force Failed Logon Detection`

It is enabled, scheduled every five minutes with cron `*/5 * * * *`, searches the last five minutes, and triggers when the result count is greater than zero. The configured action is **Add to Triggered Alerts**.

A saved/enabled alert is not evidence that it fired. The captured alert details showed no fired events at that point, so scheduled firing remains a follow-up task.

## Original screenshot evidence

These original PNG captures are attached without changing their pixels. Search results, saved configurations and scheduled triggers are identified separately.

![Case 3 — kali smb reachability case003](../screenshots/kali-smb-reachability-case003.png)

Kali confirms ICMP reachability and TCP 445 open on the Windows lab target.

![Case 3 — kali smb failed logons case003](../screenshots/kali-smb-failed-logons-case003.png)

One initial attempt and four subsequent attempts return NT_STATUS_LOGON_FAILURE; displayed passwords are deliberately incorrect test strings.

![Case 3 — splunk security 4625 raw case003](../screenshots/splunk-security-4625-raw-case003.png)

Windows Security 4625 records for SOC-Test and the controlled Kali source are indexed in Splunk.

![Case 3 — splunk brute force result case003](../screenshots/splunk-brute-force-result-case003.png)

Manual detection returns five failures for 192.168.20.20 / SOC-Test / KALI / LogonType 3, preserving first and last event times.

![Case 3 — splunk brute force alert enabled case003](../screenshots/splunk-brute-force-alert-enabled-case003.png)

SOC-002 is enabled and scheduled, with Add to Triggered Alerts configured; the capture explicitly shows no fired events.

![Case 3 — splunk successful logon check case003](../screenshots/splunk-successful-logon-check-case003.png)

The Event ID 4624 check returns zero events from 192.168.20.20 in the displayed 12:49:00–13:49:06 window; earlier activity is outside this check.

![Case 3 — splunk smb firewall correlation case003](../screenshots/splunk-smb-firewall-correlation-case003.png)

Seven parsed pfSense TCP/445 records show pass/in from Kali to Windows; firewall records and failed-logon counts are distinct.

## Analyst conclusion

The endpoint and firewall evidence correlate on source, target, service and activity window:

```text
Kali 192.168.20.20
        |
        | TCP/445
        v
pfSense — pass/in
        |
        v
Windows 11 192.168.10.100
        |
        +-- Event ID 4625 x5
        |   SOC-Test / LogonType 3 / KALI
        |
        +-- No Event ID 4624 from 192.168.20.20 in checked 1h window
```

This is a **true positive for brute-force-like failed authentication behavior** in an authorized lab exercise. No successful account compromise was observed.

## Response actions for a real SOC

For an equivalent unauthorized event:

1. Validate source ownership and expected administrative activity.
2. Check for subsequent Event ID 4624, privilege changes and suspicious process execution.
3. Review account lockouts, password-reset activity and other targeted accounts.
4. Correlate firewall, VPN, EDR and identity-provider logs.
5. Block or contain the source when appropriate to policy and confidence.
6. Protect/reset the account if compromise is suspected.
7. Escalate severity if successful authentication or post-authentication activity is found.

## Remaining work

- Capture a fired scheduled-alert entry after a fresh controlled test.
- Repeat the 4624 check with a fixed window that includes the full original failed-logon period.
- Export raw event samples for reproducibility.
- Normalize cross-host timezone handling in a later lab maintenance pass.

[Simulation](../attack-simulations/brute-force.md) · [Detection](../detections/windows-brute-force-detection.md) · [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
