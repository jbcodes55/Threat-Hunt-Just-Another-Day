[Flag4.csv](https://github.com/user-attachments/files/30321540/Flag4.csv)# Threat-Hunt-Just-Another-Day
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


<img width="468" height="250" alt="image" src="https://github.com/user-attachments/assets/2948910f-a955-4997-bd52-7a08dbd1f372" />

# Flag 2: How the Account Is Being Used

Now that I know the suspects name, I'm able to further filter using this information. Since I need the Logon type I filtered with that. Here's the query:

<img width="468" height="150" alt="image" src="https://github.com/user-attachments/assets/b88deb0f-a0c8-489a-937d-b68f0eee289b" />

After trying a few I tried "RemoteInteractive" because it makes the most because we are being inflitracted from outside the clinic.

Ans: RemoteInteractive
# Flag 3: Where the Sessions Come From

Now we need to find the IP address of where the source is coming from. We know that since the infiltrator is using a remote session, it's not within the clinic which means it's not a private ip address. I prompted ChatGPT and it gave me the following query to use.

<img width="468" height="225" alt="image" src="https://github.com/user-attachments/assets/679df1d3-a756-4ddc-b538-f7b0d86cdcea" />

Ans: 136.144.33.18
# Flag 4: Signal or Noise

ChatGPT was able to come up with the query below after I pasted the question as well as the hints that were provided.

<img width="468" height="250" alt="image" src="https://github.com/user-attachments/assets/46debf24-d8fc-4806-92cf-eb77462e3e23" />

After that I pasted the following csv results and it told me that OneDrive cleanup was likely the answer.

<img width="1433" height="546" alt="3E45394C-0562-43D9-B5B8-CDB02DC22D53" src="https://github.com/user-attachments/assets/f9d65c93-8263-4eb6-aa3f-90003c1795a2" />


Ans: OneDrive cleanup




