# pfSense configuration

pfSense is the gateway between SOC-LAB and the attacker segment.

## Document interfaces

Capture assigned interface names, lab IPs and the VirtualBox adapter mapping. Label the WAN as upstream; omit unrelated home network details.

## Rule checklist for the exercise

- Kali is connected to the attacker segment.
- The destination is the authorized Windows lab endpoint.
- The matching attacker-interface rule has logging enabled.
- Record whether the traffic was passed or blocked.
- Remote firewall logging points at the actual Splunk/syslog receiver input.

Use the narrow rule needed for the controlled exercise. Avoid publishing a complete firewall backup; it can include sensitive configuration.

## Interpreting evidence

`pass` means the firewall allowed the logged traffic; it does not prove an application accepted a connection. `block` indicates filtering at that observation point. Correlate source, destination, ports and timestamp with the recorded Kali command.

A scan on the same virtual LAN can bypass pfSense. Troubleshoot routing before concluding that missing firewall events indicate a SIEM failure.

