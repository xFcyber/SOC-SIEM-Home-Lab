# Lab screenshot evidence

Twelve original lab screenshots are included below. They were visually inspected and uploaded without changing their pixels. Captions distinguish observed state from work still pending.

## VirtualBox environment baseline — 2026-10-07

![All five SOC-LAB virtual machines running](virtualbox-machines-running.png)

Splunk-Server, Windows 11, pfSense-Firewall, Ubuntu-22,04 Server (Wazuh) and kali-linux-2024.2 are all marked **Running** in VirtualBox. This screenshot proves VM power state at capture time; it does not establish network connectivity, completed Splunk startup, agent collection or clock synchronization. Adapter configuration is still needed to confirm segmentation.

## Windows network and time baseline — 2026-10-07

![Windows IPv4, gateway and displayed clock](windows-ip-time.png)

The PowerShell output shows IPv4 **192.168.10.100**, mask **255.255.255.0**, gateway **192.168.10.1**, and displayed time **2026-10-07 14:32:59 +03:00**. These are configuration observations; reachability and cross-host clock synchronization are not demonstrated.

[Baseline details](../architecture/windows-baseline.md)

## Kali route and time baseline — 2026-10-07

![Kali eth0 address, route to Windows and timestamp](kali-ip-route-time.png)

Kali's eth0 is UP at **192.168.20.20/24**. The selected route to **192.168.10.100** uses **192.168.20.1** and source **192.168.20.20**. This shows the routing decision, not a successful connection.

The displayed timestamp **2026-10-07T08:00:35-04:00** represents **15:00:35 at UTC+03:00**. In this initial capture, the timezone differs from Windows; synchronization has not been established.

[Baseline details](../architecture/kali-baseline.md)

## Kali timezone follow-up — 2026-10-07

![Kali timezone corrected with NTP inactive](kali-timezone-ntp-inactive.png)

`timedatectl` shows **Asia/Riyadh (+03, +0300)** and local time **2026-10-07 15:12:00 +03**. It also reports **System clock synchronized: no** and **NTP service: inactive**. The timezone change is confirmed; network time synchronization remains pending.

[Baseline details](../architecture/kali-baseline.md)

## Kali gateway reachability — 2026-10-07

![Successful ping from Kali to its next hop](kali-gateway-ping.png)

The command `ping -c 4 192.168.20.1` returns **4 transmitted, 4 received, 0% packet loss**, with average RTT **25.258 ms**. This confirms ICMP reachability to the selected next hop. Windows reachability is checked in the following capture; Splunk reachability remains pending.

[Baseline details](../architecture/kali-baseline.md)

## Kali to Windows reachability — 2026-10-07

![Successful ping from Kali to Windows](kali-windows-ping.png)

The command `ping -c 4 192.168.10.100` returns **4 transmitted, 4 received, 0% packet loss**, with average RTT **7.233 ms** and reply TTL **127**. This confirms ICMP reachability to the Windows endpoint address. TCP service access and log ingestion require separate validation.

[Baseline details](../architecture/kali-baseline.md)

## Splunk address and startup — 2026-10-07

![Splunk startup and enp0s3 address](splunk-ip-startup.png)

`ip -br addr` shows **enp0s3 UP, 192.168.10.20/24**. Startup output reports `splunkd` started and the local web check on **127.0.0.1:8000** completed. The installation manifest path identifies version **10.4.3**.

A kernel watchdog soft-lockup message for CPU#1 is visible; its cause is not determined. Current receiving sockets and fresh ingestion are not demonstrated.

[Baseline details](../architecture/splunk-baseline.md)

## Firewall events collected in Splunk

![Raw pfSense filterlog events](splunk-pfsense-raw-events.png)

The screenshot shows 19 results in its selected 15-minute window, filterlog CSV events, source `192.168.20.100`, destination `192.168.10.100`, and receiver metadata `udp:5514`. See the [case analysis](../investigations/incident-001-port-scan.md) for timestamp limitations.

## Parsed firewall events

![Actual field-extraction search](splunk-pfsense-parsed-events.png)

An actual search displays 21 results over a different 60-minute window. TCP fields and pass/block actions are visible. The historical query also parses ICMP rows as though they had TCP ports; the revised query excludes them. This image does not show the revised grouped analytic.

## Saved scheduled alert

![Saved alert with no fired events](splunk-alert-enabled-no-fires.png)

The alert is enabled and scheduled. The page explicitly shows **no fired events** at the captured time. The exact cron expression and a successful scheduled run are not visible.

## pfSense OPT1 rule in progress

![OPT1 rule with unapplied changes](pfsense-opt1-rule-pending.png)

The exercise rule is present, but the **Apply Changes** banner is still visible. This documents setup in progress rather than proof that the pictured rule was active.

## Wazuh connected endpoint

![Active windows-lab agent in Wazuh](wazuh-agent-active.png)

The Wazuh endpoint page shows **windows-lab**, ID **001**, status **active**, host **WINDOWS11OFF**, and last keep alive **Oct 5, 2026 @ 11:17:05.000**. The dashboard URL is `192.168.10.10`.

Summary charts are visible, but individual event details are not. Technique/compliance summaries do not independently prove those behaviors occurred or compliance was achieved.

## Evidence still needed

| Suggested filename | Required proof |
| --- | --- |
| virtualbox-network.png | VM adapter names and segmentation |
| pfsense-syslog.png | Actual remote logging destination |
| splunk-receiver.png | TCP 9997 receiving input |
| windows-forwarder-active.png | Active endpoint forwarding |
| windows-sysmon-event1.png | Local Sysmon process creation |
| splunk-sysmon-event.png | Matching indexed Sysmon event |
| kali-port-scan.png | Real command, target, source identity and output |
| splunk-port-scan-result.png | Revised analytic's grouped result |
| splunk-alert-schedule.png | Actual cron and time-window settings |
| splunk-triggered-alert.png | Successful scheduled trigger |
| wazuh-event-details.png | Individual collected event or alert |

Add only real evidence. Do not infer missing values from screenshots or substitute generated interface images.
