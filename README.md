
  $${{\color{Orange}\huge{\textsf{Threat Hunt Report: Deep Access:The Adversary\ }}}}\$$

---
$${{\color{Silver}\huge{\textsf{Scenario  }}}}\$$

---
For weeks, multiple partner organizations across Southeast Asia and Eastern Europe detected odd outbound activity to obscure cloud endpoints. Initially dismissed as harmless automation, the anomalies began aligning.

Across sectors — telecom, defense, manufacturing — analysts observed the same patterns: irregular PowerShell bursts, unexplained registry changes, and credential traces mimicking known red-team tools.

Then came a break. A tech firm flagged sensitive project files leaked days before a bid was undercut. An energy provider found zipped payloads posing as sync utilities in public directories.

Whispers grew — not one actor, but a coordinated effort. Code fragments matched across unrelated environments. The beaconing continued: quiet, rhythmic pings to endpoints no business could explain.

Some suspect Starlance — an old, disbanded joint op revived. Others say mercenary crews using supply chain access and familiar tooling.

What’s clear: this wasn’t smash-and-grab. It was long game.

Your task: trace the access, map the spread, and uncover what was touched — or taken. Two machines hold the truth, scattered and shrouded.

No alerts fired. No passwords changed.
But something was here…
…and it might return.

<div align="center">
 <img src =https://github.com/user-attachments/assets/1d94b9fe-bd19-4e9a-b130-5dd7ffb2c4d5 width="500">
</div>
  </br>

${{\color{Orange}\huge{\textsf{Flag - by - Flag Analysis\ }}}}\$
## Starting point
  - Before you officially begin the flags, you must first determine where to start hunting. The attack points are randomized, but you may want to start with the newly created virtual machines that were only active for a few hours before being deleted, implying that the device(s) did not generate thousands of recorded processes, at least not in the central logging repository. 

a. Around May 24th 2025

The hunt begin by determining the device in which attacks were initiated, in which i utilized the timestamp explanding to a day before and a day after.

📌 *Answer:* `Acolyte756`

Query Used
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-05-23 00:00:00) ..datetime(2025-05-25 23:59:59) )
|summarize ProcessCount = count()by DeviceName
| where DeviceName startswith "a"
|order by ProcessCount asc
```
## Flag 1 – Initial PowerShell Execution Detection

*Objective*:
Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

*What to Hunt*:
Initial signs of PowerShell being used in a way that deviates from baseline usage.

*Thought*:
Understanding where it all began helps chart every move that follows. Look for PowerShell actions that started the chain.

When was the first PowerShell activity in the system?

${{\color{Yellow}\large{\textsf{Though Process\ }}}}\$

>After identifying Acolyte756 as the likely initial attack vector (based on unusually low process counts during the suspected time window), I focused my search specifically on this device.
>Since PowerShell is a common initial execution vector for attackers, especially when paired with fileless or scripted payloads, I filtered for executions of powershell.exe.
>
>I deliberately filtered on both:
>
>InitiatingProcessFileName == "powershell.exe"
>FileName has "Powershell.exe"
>...to ensure I caught both parent and actual process names, regardless of casing inconsistencies. This is important when >adversaries use nested or chained execution.
>
>I sorted the results chronologically to identify the first observed instance, knowing that early execution is often where the payload or stager runs.

${{\color{Orange}\large{\textsf{📌 Answer: 2025-05-25T09:14:02.3908261Z}}}}$

Query Used
```
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where InitiatingProcessFileName == "powershell.exe"
| where FileName has "Powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```
## Flag 2 –  Suspicious Outbound Signal
*Objective*
Confirm an unusual outbound communication attempt from a potentially compromised host.

*What to Hunt*:
External destinations unrelated to normal business operations.

*Thought*:
When machines talk out of turn, it could be a sign of control being handed off.

*Hint*: 
1. We don't have a controlled remote server
2. hollow tube

Figure out the unusual outbound connection?

${{\color{Orange}\large{\textsf{📌 Answer: }}}}$$`eoqsu1hq6e9ulga.m.pipedream.net`

Query Used
```
DeviceNetworkEvents
| where DeviceName == "acolyte756"
| where RemoteUrl != "" or RemoteIPType == "Public"
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windowsupdate"
| where InitiatingProcessFileName has_any ("powershell.exe", "cmd.exe", "wscript.exe", "curl.exe", "wget.exe")
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, Protocol, RemotePort
| order by Timestamp desc
```
## Flag 3 –  Segistry-based Autorun Setup
*Objective*:
Detect whether the adversary used registry-based mechanisms to gain persistence.

*What to Hunt*:
Name of the program tied to the new registry value created.

*Thought*:
Registry is a favored place to hide re-execution logic — it’s reliable, stealthy, and usually overlooked.

Identify the file associated with the newly created registry value?

${{\color{Yellow}\large{\textsf{Though Process\ }}}}\$

>I knew from prior flags that the attacker used PowerShell for execution, so I looked for registry keys created by powershell.exe.
>I filtered on RegistryValueData and expanded entries manually to find anything that looked like a script path or encoded command.

${{\color{Orange}\large{\textsf{📌 Answer:C2.ps1}}}}$

Query Used
```
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where InitiatingProcessFileName has_any ("powershell.exe")
| project RegistryValueData, Timestamp, RegistryKey,RegistryValueName,InitiatingProcessFileName,InitiatingProcessCommandLine,InitiatingProcessFolderPath
// timestamp 2025-05-25T09:14:02.7132107Z
```
## Flag 4 –  Scheduled Task Persistence
*Objective*:
Investigate the presence of alternate autorun methods used by the intruder.

*What to Hunt*:
Verify if schedule task creation occurred in the system. 

*Thought*:
Adversaries rarely rely on just one persistence method. Scheduled tasks offer stealth and reliability — track anomalies in their creation times and descriptions.

Identify the earliest registry value tied to the schedule task creation?

${{\color{Yellow}\large{\textsf{Though Process\ }}}}\$

>Based on the though process and flag title to look for scheduled task, I decided to include that in my query when looking for the answer.Based on the previous flag, I noticed after explanding the registry key field that at the end of the value it mentioned SimC2Task. The earliest task occurs at 2025-05-25T09:14:05.0880043Z.

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$ `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SimC2Task`

Query Used
```
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where RegistryKey contains "Schedule" // Focus on Task Scheduler registry entries
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```
## Flag 5 –  Obfuscated PowerShell Execution
*Objective:*
Uncover signs of script concealment or encoding in command-line activity.

*What to Hunt*:
Look for PowerShell patterns that don't immediately reveal their purpose — decoding may be required.

*Thought*:
Encoding is a cloak. Finding it means someone may be hiding something deeper within an otherwise familiar tool.

*Hint*: 
1. "Simulated obfuscated execution"

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$ `"powershell.exe" -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAaQBtAHUAbABhAHQAZQBkACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA`

Query Used
```
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where Timestamp between (datetime(2025-05-25 00:00:00) .. datetime(2025-05-25 23:59:59))  // Full day of May 25, 2025
| where InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-Command", "base64")  // Look for encoded PowerShell execution patterns
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```
## Flag 6 –  Evasion via Legacy Scripting
*Objective:*
Detect usage of outdated script configurations likely intended to bypass modern controls.

*What to Hunt:*
Look for uncommon scripting version of PowerShell or execution flags that reduce oversight.

*Thought:*
Modern defenses expect modern behavior. Watch for forced downgrades or legacy runtime calls.

Provide the command value used to downgrade PowerShell?

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$`"powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit`

Query Used
```
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine has_any ("-Version", "2.0", "-ExecutionPolicy Bypass")  // Look for downgrade flags
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```
## Flag 7 – Remote Movement Discovery
*Objective:*
Reveal the intruder's next target beyond the initial breach point.

*What to Hunt:*
Trace outbound command patterns that reference hostnames unfamiliar to the local machine.

*Thought:*
Lateral movement often hides in plain sight. Connections to the right system at the wrong time can be the giveaway.

What is the name of the next potentially compromised machine?

${{\color{Yellow}\large{\textsf{Though Process\ }}}}\$

>While searching through the logs for the previous flag, I noticed that a few of the proccess command line displayed another device within their field. The field also showed credentials used to and cmd.exe as the filename indicating that a remote session was initiated from acolyte756 indicating lateral movement.


${{\color{Orange}\large{\textsf{📌 Answer:victor-disa-vm}}}}$


## Flag 8 – Remote
Identify the subtle digital footprints left during a pivot.

*What to Hunt:*
Artifacts with naming patterns that imply staging, sync, or checkpointing.

*Thought:*
Every move leaves a mark — even if that mark is as simple as a filename that doesn't belong.

*Hint:*
1. point

Identify the name of the lateral entry point?

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$`savepoint_sync.lnk`

Query Used
```
DeviceFileEvents
| where DeviceName == "victor-disa-vm"  // Replace with the second compromised host
| where FileName has_any ("staging", "checkpoint", "sync", "update", "test", "tmp")  // Look for specific suspicious naming patterns
| where FileName contains "point"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
| order by Timestamp desc
```
## Flag 8.1 –  Persistence Registration on Entry
*Objective:*
Detect attempts to embed control mechanisms within system configuration.

*What to Hunt:*
Registry values tied to files or commands that were not present days before.

*Thought:*
Nothing says ownership like persistence. Look for traces that don’t match the system’s normal operational cadence.

*Hint:* 
1. Utilize previous findings

Figure out the registry data value associated?

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$`"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"`

Query Used
```
DeviceRegistryEvents
| where DeviceName == "victor-disa-vm"  // Replace with the compromised host name
| where RegistryKey has_any ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache")
| where RegistryValueData has_any ("staging", "checkpoint", "sync", "update", "test", "tmp")  // Match file names found in previous query
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```
## Flag 9 –  External Communication Re-established
*Objective:*
Verify if outbound signals continued from the newly touched system.

*What to Hunt:*
Remote destinations not associated with the organization’s known assets.

*Thought:*
When one door closes, another beacon opens. Follow the whispers outbound.

*Hint:* 
1. Utilize previous findings

Search for the suspicious outbound connection?

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$`"eo1v1texxlrdq3v.m.pipedream.net"`

Query Used
```
DeviceNetworkEvents
| where DeviceName == "victor-disa-vm"
| where RemoteUrl != "" or RemoteIPType == "Public"
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windowsupdate"
| where InitiatingProcessFileName has_any ("powershell.exe", "cmd.exe", "wscript.exe", "curl.exe", "wget.exe")
| order by Timestamp desc
```
## Flag 10 –  Stealth Mechanism Registration
*Objective:*
Uncover non-traditional persistence mechanisms leveraging system instrumentation.

*What to Hunt:*
Execution patterns or command traces that silently embed PowerShell scripts via background system monitors.

*Thought:*
Some persistence methods don’t rely on scheduled tasks or run keys. Instead, they exploit Windows Management Instrumentation (WMI) to bind code to system behavior — event filters, consumers, and bindings quietly forming a re-execution trap.
If successful, the attacker no longer needs a login or shell to keep control.

*Hint:* 
1. Report has it that a program containing a name "beacon" has done similar activity in other departments.

Identify the earliest activity time tied to WMI persistence this time?

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$`2025-05-26T02:48:07.2900744Z`

Query Used
```
/// Part 2: Find PowerShell executions triggered by WMI (likely malicious)
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName =~ "wmiprvse.exe"  // WMI-hosted script execution
| where ProcessCommandLine has "beacon" or ProcessCommandLine has_cs "-nop -w hidden -e"  // Common PS attack patterns
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| sort by Timestamp asc

DeviceProcessEvents // Adjust timeframe if needed
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName =~ "wmiprvse.exe"  // WMI-triggered execution
| where ProcessCommandLine has @"C:\Users\Public\beacon_sync_job_flag2.ps1"  // Target script
| project 
    Timestamp,
    DeviceName,
    ProcessCommandLine,
    InitiatingProcessFileName = InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| sort by Timestamp asc  // Find the FIRST occurrence (earliest compromise)
```
## Flag 11 –  Suspicious Data Access Simulation
*Objective:*
Detect test-like access patterns mimicking sensitive credential theft.

*What to Hunt:*
References or interactions with files suggestive of password storage or system secrets.

*Thought:*
Even simulations create signals. Mimicry of real attacks is often part of preparation.

*Hint:* 
1. Possible Mimikatz variations
   
What is the name of the file deployed attempting to perform credential dumping?

${{\color{Yellow}\large{\textsf{Though Process\ }}}}\$

>I intially started this query believe that there was another device involved, however after going down a rabbit hole I decided to return my focus to the device victor-disa-vm. Additionally, the hint mentioned possible variation of mimikatz. I leveraged chat gpt and focused my queries to look for file ending such as .dmp, dump. and those containing mimikatz nd lsass in teir name. However, this returned nothing. So I eventually, realized that I may be overthinking and implified my search to jst focus on filenames containing mim.

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$ `mimidump_sim.txt`

Query Used
```
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"  // Replace with the second compromised host
| where FileName contains "mim" or ProcessCommandLine contains "mim"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp desc
```
## Flag 12 – Unusual Outbound Transfer

*Objective:*
Investigate signs of potential data transfer to untrusted locations.

*What to Hunt:*
External destinations indicative of third-party file storage or sharing services.

*Thought:*
The hands that take may hide in common destinations. Even familiar URLs can hide foul intent.

What is the SHA256 value of the associated process?

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$`9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`

Query Used 
```
DeviceNetworkEvents
| where RemoteUrl in ("eo1v1texxlrdq3v.m.pipedream.net", "eoqsu1hq6e9ulga.m.pipedream.net")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, RemoteUrl
| order by Timestamp desc
```
## Flag 13 – Sensitive Asset Interaction
*Objective:*
Reveal whether any internal document of significance was involved.

*What to Hunt:*
Access logs involving time-sensitive or project-critical files.

*Thought:*
When the adversary browses project plans, it’s not just about access — it’s about intent.

*Hint:*
1. Organization suspects the adversary may have been targeting a document related to this year's end month projects (yyyy-mm)

What file were the attackers trying to target this time?

${{\color{Yellow}\large{\textsf{Though Process\ }}}}\$

>I initially believed that the document was formated based on the hint as I found a few documents scuh as 2025-01.lnk. None of these documents were the solution to the flag.So out of my resuts I decided to focus on distinct filenames. Upon investigating te results I felt that of the results the only ones that captured my eye were the startegic plan, rollout plan and employee data as files that the aversary may target.

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$`RolloutPlan_v8_477.docx`

Query Used 
```
//to find 2025-12.lnk
DeviceFileEvents
| where DeviceName == "victor-disa-vm" 
| where FileName endswith ".lnk" or FileName endswith ".docx" or FileName endswith ".pdf" or FileName endswith ".csv" or FileName endswith ".txt" or FileName endswith ".xml"
| where FileName contains_cs "RolloutPlan" or FileName contains_cs "StrategicPlan" or FileName contains_cs "2025"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, ActionType
| order by Timestamp desc
|distinct FileName,DeviceName,InitiatingProcessFileName, FolderPath
```
## Flag 14 – Tool Packaging Activity
*Objective:*
Spot behaviors related to preparing code or scripts for movement.

*What to Hunt:*
Compression or packaging of local assets in non-administrative directories.

*Thought:*
Before things move, they are prepared. Track the moment code becomes cargo.

Identify the command used to compress the malicious tool?

${{\color{Yellow}\large{\textsf{Though Process\ }}}}\$

>Based on the flag asking to identify the command to compress the malicious tool. I focused on considering compress-archive within my query to discover the flag. Additionally based on the mention of a command being used, I also ,ade sure to focus on the incusion of powershell.

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$`"powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command Compress-Archive -Path "C:\Users\Public\dropzone_spicy" -DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip" -Force`

Query Used
```
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "Compress-Archive"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

## Flag 15 – Deployment Artifact Planted
*Objective:*
Verify whether staged payloads were saved to disk.

*What to Hunt:*
Unusual file drops, especially compressed archives, in public or shared paths.

*Thought:*
Staged doesn’t mean executed — yet. But it’s the clearest sign something is about to happen.

*Hint: *
1. Utilize previous findings

Identify the malicious tool in question?

${{\color{Yellow}\large{\textsf{Though Process\ }}}}\$

>Using the query from Flag 14,in the destination path there is te mention of spicycore_loader_flag8.zip. 

${{\color{Orange}\large{\textsf{📌 Answer:}}}}$`spicycore_loader_flag8.zip`

Query Used
```
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "Compress-Archive"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```
