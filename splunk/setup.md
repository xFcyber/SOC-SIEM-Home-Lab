# Splunk setup and validation

The [current server screenshot](../architecture/splunk-baseline.md) confirms `192.168.10.20/24` on `enp0s3` and completed daemon/local web startup checks. Receiver validation and fresh ingestion remain pending.

## Checks

1. Confirm the VM is reachable from SOC-LAB and open Splunk Web on port 8000.
2. Check the configured receiving input on TCP 9997.
3. On Windows, check the Universal Forwarder's forwarding status.
4. Search the actual indexes over a time range covering your exercise.
5. Compare a local Sysmon event with an indexed event and a firewall event with its indexed copy.

Read-only server check:

```bash
sudo ss -lntup
```

Inspect TCP 8000 (web), TCP 9997 (forwarders) and UDP 5514 (firewall syslog), including bind addresses and owning processes.

PowerShell network check from Windows:

```powershell
Test-NetConnection 192.168.10.20 -Port 9997
```

A listening port or successful TCP check proves transport reachability, not ingestion.

## Ingestion overview

```spl
index=pfSense "filterlog"
| stats count min(_time) as first_seen max(_time) as last_seen by host source sourcetype
| convert ctime(first_seen) ctime(last_seen)
```

```spl
index=main source="*Sysmon*"
| stats count by host source sourcetype
```

If the second search returns no events, inspect metadata in `index=main`; do not assume your source naming matches this example.

Attach receiver configuration, an active forwarder view and a sanitized event. Record installed versions from the actual VMs.

