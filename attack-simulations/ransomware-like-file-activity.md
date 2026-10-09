# Controlled ransomware-like file activity

**Exercise date:** 2026-10-09  
**Scope:** Authorized SOC home lab only.

This exercise simulated ransomware-like mass file activity without encrypting or deleting real user data.

## Safety model

A dedicated lab directory was used:

```text
C:\Users\Public\SOC-RANSOMWARE-LAB
```

The simulation created test documents and then generated additional files using ransomware-like extensions such as `.locked` and `.encrypted`. The original files remained intact.

A harmless ransom-note-style marker was also created:

```text
README_RECOVER_FILES.txt
```

No real cryptography, destructive deletion, credential theft, persistence, external communication, or production data was involved.

## Telemetry challenge and resolution

The first attempt relied on Sysmon Event ID 11, but the active Sysmon configuration did not expose the test file creations in Splunk.

Rather than replace the working Sysmon configuration, the lab enabled Windows **File System** auditing and added a success-audit rule only to the dedicated test directory.

Windows then produced Security Event ID **4663 — An attempt was made to access an object** for the test files.

## Validation batches

The first audited validation batch created 20 files:

```text
RUN2_1.encrypted
...
RUN2_20.encrypted
```

Splunk correlated all 20 distinct files to PowerShell in the same minute.

After the alert was saved, a second batch created 15 additional files with a `.locked` extension to validate the scheduled alert.

## ATT&CK mapping

**T1486 — Data Encrypted for Impact**

This mapping represents the behavior being simulated. The lab did **not** perform real encryption.

[Detection analytic](../detections/ransomware-mass-file-activity.md) · [Investigation](../investigations/incident-006-ransomware-like-file-activity.md)
