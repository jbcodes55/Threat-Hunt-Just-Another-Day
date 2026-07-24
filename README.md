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

After prompting ChatGPT on the question, it produced a similar query to the one above. One of the hints said the folder I'm looking for is in the "approval stage" which hinted at the correct answer after seeing the query results.

<img width="468" height="192" alt="image" src="https://github.com/user-attachments/assets/d930d157-99f3-4b83-9b77-0a4af1a96eff" />

Ans: Approved

# Flag 10: The Invoice
Here I had to find the invoice (filename) that the account handled in the approval folder. Based off my earlier findings, ChatGPT immediately recognized the correct filename and gave me the following query to use.


<img width="468" height="192" alt="image" src="https://github.com/user-attachments/assets/25d80ac8-8663-47c0-82dc-792872040711" />

Result:

<img width="918" height="151" alt="3E077F1E-8766-47FA-9F05-E1DA8B1AD7D5_4_5005_c" src="https://github.com/user-attachments/assets/a2440fa2-e278-45f0-8731-1b079b211210" />

Ans: approved_pending_invoice_INV-773221_20260311.txt

# Flag 11: The Audit Trail

The question says the infiltrator touched the audit trail, and to name the audit file that was assessed. So it was obvious that the query I needed to use should filter files that had the word "audit" in them. This is the query I used below

Query Used:

<img width="468" height="242" alt="image" src="https://github.com/user-attachments/assets/b2e7ae3f-5573-4759-be95-2cd2d6f10bcc" />

After trying to submit the answer with the .csv extension, I tried with the .txt extension which was the right answer.

Ans: review_audit_20260311.txt 

# Flag 12: Staged Under Cover

I prompted ChatGPT for this question and the hints the question provided allowed me to narrow down my search considerably. I'm looking for a file that was renamed to avoid suspision and placed in the billing folder. I tried this query but it didn't yield any results.

<img width="468" height="101" alt="image" src="https://github.com/user-attachments/assets/29f33f26-8c85-45bb-a993-50e9dc1dbec1" />

Then I tried just searching for the extension ".txt.txt" that one of the hints suggested and did the following query:

<img width="468" height="117" alt="image" src="https://github.com/user-attachments/assets/bd70efd7-5c7d-44bd-81d9-fa8e0677b7f0" />

Query Results:

<img width="1104" height="342" alt="826BD646-21AC-4F92-AAAB-086A9FB13DA8_4_5005_c" src="https://github.com/user-attachments/assets/ec80cd91-12c3-4b29-b277-2f29936d2f70" />

After looking through the results I saw a file was renamed and modified under j.morris in the billing folder which lead me to the answer.

Ans: temp_payroll_review_jmorris_20260311.txt.txt

# Flag 13:  The Second Target
Unlocking the hints for this question helped a lot. The file that I'm looking for was in the Awards folder from this provided path "HR\2026-03\Awards". I used the following query and set the time range as custom:

<img width="468" height="175" alt="image" src="https://github.com/user-attachments/assets/91a5a5e4-0589-4693-a2cf-0b3056ea5d34" />

Query Results:

<img width="1194" height="161" alt="93E1660C-83C5-4CD9-A54C-CDB1B45B3C9E_4_5005_c" src="https://github.com/user-attachments/assets/0f8f480b-b657-429d-848f-ba6f028a4156" />

This query provides the correct answer however I changed the extension to .txt because it's been a common thing that the .lnk extension some of my queries give me is incorrect. I was right to do so.

Ans: quarterly_awards_shortlist_20260310.txt

# Flag 14: The Onward Hops
Here the question is asking me to find the other devices where remote sessions were established by the infiltrator. Since we know that the infiltrator used a "RemoteInteractive" logontype from before and we know his IP address, I just needed to filter by distinct device names with the following query:

Query Used:

<img width="468" height="150" alt="image" src="https://github.com/user-attachments/assets/8de0d3df-6bcb-4944-aee1-0f1aeb207a64" />

Query Results:

<img width="264" height="124" alt="73917325-DBB5-477B-A70A-38F2E9172B72_4_5005_c" src="https://github.com/user-attachments/assets/053413b7-e47e-4af8-aabe-c0488dbc0391" />

Ans: nh-wks-it-01, nh-fs-01

# Flag 15: The Red Herring
The question is asking to prove that one of the hops from the previous question is a red herring. 
Just pasting the question into ChatGPT gave me the correct answer from the data it's received from previous queries, no extra query was needed for this question.

Ans: Profile initialization only; no hands-on activity

# Flag 16: Checking Their Rights

This flag is asking me to find which command the account's operator used to find the privileges and groups they had. Using the information it already had and the extra hints, ChatGPT suggested the answer was whoami /groups  which was correct.

Ans: whoami /groups 

# Flag 17: What the Server Offered

This question wants the command that was used right after the previous one to enumerate the file server. This flag hints at using a net command and after pasting the question into ChatGPT it gave me the correct answer.

Ans: net share

# Flag 18: Someone Else's Payroll

HUNT LEAD: "The last thing they did on the file server was open a payroll review belonging to a different employee entirely. Name the file, and note whose it is."

This was another question that was easily solvable thanks to it's hints. ChatGPT noted a filename in particular from my previous queries which resulted in the answer.

Ans: payroll_review_dpatel_20260311.txt

# Flag 19: What Else Left HR

This flag wants me to explain the what was taken out of HR. Pasting the question into ChatGPT gave me the answer.

Ans: Targeted multi-file HR collection spanning payroll and employee awards data

# Flag 20: The Honest Read

Now that there's evidence that this wasn't just a curious employee, this flag wants me to summarize why we know it was an outsider. ChatGPT gave me the answer.

Ans: External compromise using valid credentials from outside the network; no malware or exploit artifacts, only native Windows tools. 
