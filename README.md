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

That returned too many AccountNames so I decided to filter more by the ProcessCommandLine or the FileName to see who could be running commands in a billing account which is told to us by the flag description.

I used the following query where I tried a few names one of which being the answer:

DeviceProcessEvents
-| where DeviceName startswith "nh-"
-| where ProcessCommandLine has_any ("billing", "invoice", "payment", "account")
   -or FileName has_any ("billing", "invoice", "payment")
-| project Timestamp,
         - DeviceName,
         - AccountName,
         - FileName,
         - ProcessCommandLine
<img width="468" height="250" alt="image" src="https://github.com/user-attachments/assets/2948910f-a955-4997-bd52-7a08dbd1f372" />
