# Controlled SMB failed-login simulation

**Exercise date:** 2026-10-08  
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

## Safety and scope

This simulation was restricted to owned lab VMs and a dedicated test account. It was not used against an external system or production account.

[Detection analytic](../detections/windows-brute-force-detection.md) · [Investigation](../investigations/incident-003-brute-force.md)
