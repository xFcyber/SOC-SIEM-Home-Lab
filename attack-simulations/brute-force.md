# Controlled SMB failed-login simulation

**Exercise dates:** 2026-10-08; scheduled-alert retest 2026-10-09  
**Scope:** Authorized SOC home lab only.

This exercise generated a small, controlled set of failed SMB authentications from Kali Linux to the Windows 11 lab endpoint so the events could be detected and investigated in Splunk.

## Lab roles

| Role | Address / value |
| --- | --- |
| Kali attacker VM | 192.168.20.20 |
| Windows 11 target | 192.168.10.100 |
| pfSense | routes attacker traffic into SOC-LAB and forwards filterlog to Splunk |
| Splunk | 192.168.10.20:8000 |
| Test account | `SOC-Test` |
| Target service | SMB / TCP 445 |

The Kali path was verified before the test: TCP 445 on the Windows target was reachable through pfSense.

## Controlled execution

Five deliberately incorrect passwords were attempted against the lab-only account:

```bash
for pass in WrongPass1 WrongPass2 WrongPass3 WrongPass4 WrongPass5; do
    echo "Trying password: $pass"
    smbclient -L //192.168.10.100 -U "SOC-Test%$pass" -m SMB3
    sleep 2
done
```

The captured Kali output returned `NT_STATUS_LOGON_FAILURE` for the attempts. The correct account password is intentionally not documented.

The Windows local account policy showed a lockout threshold of 10 attempts, so the exercise was limited to five failures to avoid intentionally locking the account.

## Expected and observed telemetry

Windows Security auditing generated Event ID **4625** for failed logons. Splunk received the Security channel in index `security_logs` with source `WinEventLog:Security` and sourcetype `XmlWinEventLog:Security`.

The correlated detection result identified:

- Source IP: **192.168.20.20**
- Target account: **SOC-Test**
- Failed events: **5**
- Workstation: **KALI**
- Logon type: **3 — Network**
- Target path: Windows 11 over **TCP 445 / SMB**

pfSense independently recorded inbound TCP traffic from 192.168.20.20 to 192.168.10.100:445 around the same exercise window.

## Fresh scheduled-alert retest — 2026-10-09

The same bounded five-attempt SMB simulation was repeated from Kali. Every attempt returned `NT_STATUS_LOGON_FAILURE`; only deliberately incorrect test strings are displayed.

![Fresh five-attempt Kali SMB test](../screenshots/kali-smb-failed-logons-retest-20261009-case003.png)

The existing `SOC-002 - Brute Force Failed Logon Detection` alert fired at **2026-10-09 17:50:01 UTC (20:50:01 Asia/Riyadh)**. The scheduled **View Results** job returned **5 events / 1 grouped result** for **192.168.20.20 / SOC-Test / KALI / LogonType 3**. See [case 003](../investigations/incident-003-brute-force.md#evidence-6--fresh-scheduled-alert-validation--2026-10-09) for the original Trigger History and results captures. A full-window successful-logon check for this retest remains pending.

## Safety and scope

This simulation was restricted to owned lab VMs and a dedicated test account. It was not used against an external system or production account.

[Detection analytic](../detections/windows-brute-force-detection.md) · [Investigation](../investigations/incident-003-brute-force.md)
