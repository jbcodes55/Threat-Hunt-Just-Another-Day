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

# Flag 5: Getting Their Bearings
This flag was pretty simple because it basically was only asking for me to analyze my previous query and find a sequence of answers that the query already produced. I just needed to modify the query slightly and I was able to get the answer.

<img width="468" height="209" alt="image" src="https://github.com/user-attachments/assets/10757b58-a187-4f7e-80fa-1b23bb0d3303" />

Ans: whoami,hostname,net use,net view,net view \\NH-FS-01

# Flag 6: The Named Target
This flag didn't requie any extra work because the answer from number 5 already provides it. It's asking for the last command of flag 5, which is NH-FS-01/

Ans: NH-FS-01

# Flag 7: Widening the Net
This flag wants me to find the command that was used by the infiltrator after coming back to the shell terminal. The hints and the name of the flag itself is hinting at a command that has the word "net" in it. I used this information for the query below. 

<img width="468" height="175" alt="image" src="https://github.com/user-attachments/assets/9d1b3ca1-6529-49ef-92e8-e91294cbf803" />

To get the answer I just tried the different commands in the below CSV until I got to the correct one.

Query Results:
<img width="450" height="287" alt="4531C1D9-89C9-4D0C-95F8-96AC5E1CDE8E_4_5005_c" src="https://github.com/user-attachments/assets/3ded8402-e0a6-49a8-9b6d-8085b0017c16" />

Ans: "net.exe" view /domain:nimbus

# Flag 8: Mapping Before the Jump
This flag wants me to see what they were doing in a two minute interval from the last command. I already knew which date to use in our query because the last csv results told me the date when the infiltrator used the net command. A hint further narrowed down my search from 1:18pm to 1:20pm. 

Query Used:

<img width="468" height="192" alt="image" src="https://github.com/user-attachments/assets/0a95934a-b05d-46f7-9d76-215b142c9acb" />

Pasting the csv query results into ChatGPT gave me the following answer

Ans: ARP enumeration and nslookup reconnaissance, RDP pivot to another host

# Flag 9: Out of Role


