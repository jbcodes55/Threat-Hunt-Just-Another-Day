# Threat-Hunt-Just-Another-Day
I completed the "Just-Another-Day" threat hunt in the cyber range.

# Platforms and Tools Used
- Platform: Microsoft Defender for Endpoint (MDE), Log Analytics Workspace, Windows
- Languages & Tools: Kusto Query Language (KQL)

---
# Scenario Summary

Nimbus Health, a small outpatient clinic we support, asked for a posture review after a billing account showed some odd activity. The paperwork calls it a stale-access housekeeping check. Read it as an investigation anyway, and let the telemetry decide what it actually is.

The account in question belongs to a billing analyst. On paper, submissions work, nothing more. In the logs, that account is doing things a billing analyst has no business doing, and it's being used in a way that should make you look twice at where it's being used from.

---

# Flag Analysis and Findings

# Flag 1: The Account Under Review

I started by looking at the different accountnames by using the following query:

DeviceProcessEvents
| where DeviceName startswith "nh-"

