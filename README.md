# Threat Hunt Engagement Report: Operation Deep Access

---

## Executive Summary

This report details the findings of a proactive threat hunt, "Operation Deep Access," initiated in response to intelligence concerning coordinated anomalous outbound network activity observed across multiple partner organizations. The investigation, focused on identifying persistent footholds and lateral movement within our environment, successfully uncovered a sophisticated intrusion chain originating from a transient virtual machine, **Acolyte756**, and subsequently establishing persistence on **victor-disa-vm**. Key findings include the adversary's use of PowerShell for initial execution and persistence, leveraging scheduled tasks and WMI for stealth, and attempts at credential access and data exfiltration. The hunt revealed a methodical approach by the adversary, employing obfuscation and legacy scripting versions to evade detection. This report provides a detailed chronological breakdown of the attack, the KQL queries used for discovery, and critical indicators of compromise (IOCs) to bolster future detection and prevention efforts.

---

## Scenario: The Unseen Intrusion

For weeks, a subtle, yet unsettling pattern of outbound network activity to obscure cloud endpoints had been surfacing across our partner organizations in Southeast Asia and Eastern Europe. Initially, these anomalies were dismissed as benign automated processes. However, a deeper analysis revealed a disquieting alignment: irregular PowerShell bursts, unexplained registry modifications, and credential traces consistent with known red-team tooling began to emerge across disparate sectors, including telecom, defense, and manufacturing.

The true gravity of the situation became apparent when a technology firm reported sensitive project files leaked just days before a critical bid, and an energy provider discovered suspicious zipped payloads, masquerading as legitimate sync utilities, residing in public directories.

Whispers of a coordinated, persistent threat grew louder. Code fragments, remarkably similar, were observed across seemingly unrelated environments. The quiet, rhythmic beaconing to inexplicable external endpoints persisted, signaling a controlled and ongoing compromise.

While the precise identity of the actor remains elusive—some speculate a revival of "Starlance," a previously disbanded joint operation, while others point to mercenary groups exploiting supply chain access and familiar tools—one fact is unequivocally clear: this was not a smash-and-grab. This was a long-game operation, meticulously executed to maintain a deep, unnoticed presence.

Our mission: trace the initial access vector, map the extent of lateral propagation, and meticulously uncover what critical assets were accessed, modified, or exfiltrated. The truth, scattered and shrouded, resides within the digital footprints of two key machines.

Crucially, this adversary operated with extreme stealth. No traditional alerts fired. No overt password changes were detected. Yet, an unwelcome presence had permeated our defenses. The lingering question remains: *has the adversary truly departed, or is this merely a lull before their return?*

<div align="center">
 <img src =https://github.com/Bharathkasyap/ThreatHuntReport_Deep_Advesary/blob/main/Image.png width="500">
</div>
 </br>

---

## Chronological Hunt Narrative & Analysis

This section details the progression of the threat hunt, presenting each discovery as a step in unraveling the adversary's actions. Each flag represents a pivotal finding, supported by the KQL query used for its detection and a comprehensive thought process behind the analytical approach.

### Initial Compromise Vector Identification
*Objective*: To identify the most likely initial point of compromise within the environment, focusing on devices with anomalous activity patterns during the suspected intrusion window.

*Rationale*: Adversaries often leverage new or short-lived systems for initial staging or C2 communication to reduce their footprint and evade baselining. By prioritizing devices with minimal historical telemetry, we increase the probability of pinpointing the initial point of entry without being overwhelmed by legitimate noise.

*Timeframe of Interest*: Approximately May 24th, 2025, suggesting a window spanning a day before and a day after to capture precursor activities or immediate follow-ups.

**Query Used**:
```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-05-23 00:00:00) ..datetime(2025-05-25 23:59:59) )
|summarize ProcessCount = count()by DeviceName
| where DeviceName startswith "a"
|order by ProcessCount asc
```
Discovery: Acolyte756

### Flag 1 – Initial PowerShell Execution Detection
Objective: Pinpoint the earliest observed suspicious PowerShell activity, marking the probable initial execution phase of the intruder's operations.

What was Hunted: Instances of powershell.exe being invoked in a manner that deviates from typical baseline usage, particularly focusing on early timestamps.

Analytical Insight: The initial execution is the crucial "first ripple" in an intrusion. Understanding its specifics allows us to map the subsequent chain of events. Attackers frequently use PowerShell due to its native presence on Windows systems and its scripting capabilities for various malicious actions, including downloading payloads, executing commands, or establishing persistence.

Thought Process:
Upon identifying Acolyte756 as the most probable initial access host due to its unusually low process count within the suspected intrusion timeframe, my focus immediately shifted to analyzing its activity. Given that PowerShell is a preferred tool for initial execution and fileless attacks, I specifically filtered for powershell.exe executions. To ensure comprehensive coverage, I included both InitiatingProcessFileName == "powershell.exe" (to capture the parent process that launched PowerShell) and FileName has "Powershell.exe" (to account for the actual PowerShell process, irrespective of casing or potential renaming). This dual filter helps in catching various execution scenarios, including nested or chained PowerShell commands. Sorting chronologically was paramount to identifying the absolute first observed instance, which is often indicative of where the initial payload or stager was launched.

Discovery: 2025-05-25T09:14:02.3908261Z

Query Used:

```kusto
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where InitiatingProcessFileName == "powershell.exe"
| where FileName has "Powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```
### Flag 2 – Suspicious Outbound Command and Control (C2) Signal
Objective: To confirm the establishment of unusual outbound communication from the potentially compromised host, indicative of C2 channel establishment.

What was Hunted: External network destinations that are not legitimate business operations or common update services.

Analytical Insight: Malicious outbound connections are a hallmark of C2 activity, signifying the adversary's ability to control the compromised system remotely. Identifying these connections is critical for understanding the adversary's infrastructure and disrupting their operations. The hints "We don't have a controlled remote server" and "hollow tube" suggest a non-standard, possibly transient or public-facing C2 infrastructure.

Discovery: eoqsu1hq6e9ulga.m.pipedream.net

Query Used:

```kusto
DeviceNetworkEvents
| where DeviceName == "acolyte756"
| where RemoteUrl != "" or RemoteIPType == "Public"
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windowsupdate"
| where InitiatingProcessFileName has_any ("powershell.exe", "cmd.exe", "wscript.exe", "curl.exe", "wget.exe")
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, Protocol, RemotePort
| order by Timestamp desc
```
### Flag 3 – Registry-based Autorun Persistence Mechanism
Objective: Detect whether the adversary established persistence through standard registry-based autorun mechanisms.

What was Hunted: Newly created registry values that execute programs, particularly focusing on those initiated by PowerShell. The goal was to identify the specific program associated with this persistence.

Analytical Insight: The Windows Registry is a well-known and highly reliable location for adversaries to establish persistence. By embedding malicious commands or script paths within legitimate autorun keys, they ensure re-execution upon system restart or user login, maintaining their foothold. The focus on PowerShell as the InitiatingProcessFileName aligns with previous findings of its extensive use by the adversary.

Thought Process:
Knowing that the adversary extensively utilized PowerShell (as evidenced by previous flags), my investigation into persistence naturally led to registry modifications performed by powershell.exe. I specifically looked for common persistence locations, such as Run keys, but kept the search broad initially by examining RegistryValueData for any suspicious string patterns. Expanding the RegistryValueData field manually for relevant entries was key. The discovery of a script path or an encoded command within these values would confirm registry-based persistence.

Discovery: C2.ps1

Query Used:

```kusto
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where InitiatingProcessFileName has_any ("powershell.exe")
| project RegistryValueData, Timestamp, RegistryKey,RegistryValueName,InitiatingProcessFileName,InitiatingProcessCommandLine,InitiatingProcessFolderPath
// timestamp 2025-05-25T09:14:02.7132107Z
```
### Flag 4 – Scheduled Task Persistence: Redundant Foothold
Objective: Investigate the presence of alternate autorun methods, specifically focusing on scheduled tasks, which offer a robust and stealthy persistence mechanism.

What was Hunted: Evidence of scheduled task creation within the system, particularly identifying the earliest registry value associated with such a task.

Analytical Insight: Sophisticated adversaries rarely rely on a single persistence mechanism. Scheduled tasks are a common and effective alternative to registry run keys, offering greater flexibility in execution timing and user context, often flying under the radar of less mature detection capabilities. Anomalies in creation times or descriptions are key indicators.

Thought Process:
Given the objective to specifically look for scheduled tasks, and the previous flag's discovery of PowerShell-driven registry modifications, I refined my KQL query to target registry keys related to the Windows Task Scheduler, specifically looking for RegistryKey contains "Schedule". While reviewing the RegistryKey field of results from previous queries, I had observed a value ending in "SimC2Task", which strongly suggested a scheduled task. This observation, combined with sorting by Timestamp asc, allowed me to pinpoint the earliest registration of this task.

Discovery: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SimC2Task

Query Used:

```kusto
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where RegistryKey contains "Schedule" // Focus on Task Scheduler registry entries
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```
### Flag 5 – Obfuscated PowerShell Execution Analysis
Objective: Uncover signs of script concealment or encoding within PowerShell command-line activity, a common evasion technique.

What was Hunted: PowerShell command lines containing parameters indicative of obfuscation, such as -EncodedCommand, -Command, or references to base64.

Analytical Insight: Adversaries frequently obfuscate their PowerShell commands to evade signature-based detections and complicate analysis. Discovering encoded or hidden commands suggests a deliberate attempt to conceal malicious intent, compelling a deeper investigation into the decoded content. The hint "Simulated obfuscated execution" points towards a training or testing environment, but the technique is indicative of real-world adversary behavior.

Discovery: "powershell.exe" -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAaQBtAHUAbABhAHQAZQBkACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA

Query Used:

```kusto
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where Timestamp between (datetime(2025-05-25 00:00:00) .. datetime(2025-05-25 23:59:59))  // Full day of May 25, 2025
| where InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-Command", "base64")  // Look for encoded PowerShell execution patterns
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```
### Flag 6 – Evasion via Legacy Scripting Version
Objective: Detect the adversary's use of outdated PowerShell script configurations, likely intended to bypass modern security controls and logging.

What was Hunted: PowerShell execution flags that explicitly downgrade its version or reduce oversight, such as -Version 2 or -ExecutionPolicy Bypass.

Analytical Insight: Modern security solutions often focus on newer versions of PowerShell, which have enhanced logging and security features. By forcing a downgrade to older, less secure versions (e.g., PowerShell 2.0), attackers can exploit known vulnerabilities or simply operate in an environment with less robust telemetry, making detection harder.

Discovery: "powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit

Query Used:

```kusto
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine has_any ("-Version", "2.0", "-ExecutionPolicy Bypass")  // Look for downgrade flags
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```
### Flag 7 – Lateral Movement Discovery: Identifying the Next Target
Objective: To reveal the intruder's next target system, indicating lateral movement beyond the initial breach point.

What was Hunted: Outbound command patterns or network events that reference hostnames unfamiliar to the local machine, particularly those associated with remote execution tools or protocols.

Analytical Insight: Lateral movement is a critical phase in an attack, allowing adversaries to expand their access and reach high-value targets. Tracing connections to new systems, especially when combined with credential usage or remote execution commands, provides a clear path of the adversary's spread.

Thought Process:
While analyzing the command lines for previous PowerShell activities, I observed ProcessCommandLine entries that referenced other devices. Specifically, commands showing credentials being used in conjunction with cmd.exe as the FileName strongly suggested a remote session initiation from Acolyte756. This pattern is a classic indicator of lateral movement, as it shows an attempt to interact with another system using compromised credentials.

Discovery: victor-disa-vm

### Flag 8 – Remote Entry Point Artifacts
Objective: Identify subtle digital footprints left behind during the adversary's pivot to the newly compromised host.

What was Hunted: Artifacts (files) with naming conventions that imply staging, synchronization, or temporary storage, indicative of preparation for further actions.

Analytical Insight: Even in stealthy operations, adversaries often leave temporary files or artifacts related to their tools or staged payloads. These seemingly innocuous file names can be critical clues when correlated with the timeline of an intrusion. The hint "point" suggests a specific naming convention to look for.

Discovery: savepoint_sync.lnk

Query Used:

```kusto
DeviceFileEvents
| where DeviceName == "victor-disa-vm"  // Replace with the second compromised host
| where FileName has_any ("staging", "checkpoint", "sync", "update", "test", "tmp")  // Look for specific suspicious naming patterns
| where FileName contains "point"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
| order by Timestamp desc
```
### Flag 8.1 – Persistence Registration on New Entry Point
Objective: Detect attempts by the adversary to embed control mechanisms within the system configuration of the newly compromised host (victor-disa-vm).

What was Hunted: Registry values tied to files or commands that were not present in a clean baseline, particularly those associated with the savepoint_sync.lnk artifact found previously.

Analytical Insight: Establishing persistence on every newly compromised system is a standard adversary tactic to ensure continued access, even if their initial entry method is discovered and remediated. This reinforces the adversary's foothold. Leveraging prior findings accelerates this phase of the hunt.

Thought Process:
Building directly on the previous flag's discovery of savepoint_sync.lnk on victor-disa-vm, it was logical to assume the adversary would establish persistence related to this artifact. I focused my registry event search on common autorun locations (Run, RunOnce, TaskCache) and filtered for RegistryValueData that contained keywords related to the savepoint or sync file. This direct correlation led to the specific PowerShell command used for persistence.

Discovery: "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"

Query Used:

```kusto
DeviceRegistryEvents
| where DeviceName == "victor-disa-vm"  // Replace with the compromised host name
| where RegistryKey has_any ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache")
| where RegistryValueData has_any ("staging", "checkpoint", "sync", "update", "test", "tmp")  // Match file names found in previous query
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```
### Flag 9 – External Communication Re-established from Pivot Point
Objective: Verify if outbound communication, indicative of C2, was re-established from the newly compromised system (victor-disa-vm).

What was Hunted: Remote destinations not associated with the organization’s known legitimate assets.

Analytical Insight: Adversaries often establish new C2 channels or continue using existing ones from subsequent compromised hosts to maintain redundant control and exfiltrate data. Confirming this from victor-disa-vm validates its role as a pivot point in the attack chain.

Discovery: "eo1v1texxlrdq3v.m.pipedream.net"

Query Used:

```kusto
DeviceNetworkEvents
| where DeviceName == "victor-disa-vm"
| where RemoteUrl != "" or RemoteIPType == "Public"
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windowsupdate"
| where InitiatingProcessFileName has_any ("powershell.exe", "cmd.exe", "wscript.exe", "curl.exe", "wget.exe")
| order by Timestamp desc
```
### Flag 10 – Stealth Mechanism Registration: WMI Persistence
Objective: Uncover non-traditional persistence mechanisms, specifically those leveraging Windows Management Instrumentation (WMI), for enhanced stealth.

What was Hunted: Execution patterns or command traces that silently embed PowerShell scripts via background system monitors, specifically looking for wmiprvse.exe initiating PowerShell with suspicious parameters or script names.

Analytical Insight: WMI persistence is a highly favored technique for advanced adversaries due to its stealth and reliability. It allows code to be executed in response to system events, bypassing common scheduled task or run key monitoring. This indicates a higher level of sophistication. The hint about a "beacon" program in other departments suggests a known tool or script being re-used.

Discovery: 2025-05-26T02:48:07.2900744Z

Query Used:

```kusto
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
### Flag 11 – Suspicious Data Access Simulation: Credential Theft Attempt
Objective: Detect test-like access patterns mimicking sensitive credential theft, often a precursor to actual data exfiltration.

What was Hunted: References or interactions with files or processes suggestive of password storage or system secrets, particularly those with naming conventions similar to known credential dumping tools.

Analytical Insight: Adversaries frequently test their capabilities or simulate attacks within a compromised environment before executing their primary objectives. Activities mimicking credential dumping tools like Mimikatz are strong indicators of intent to elevate privileges or exfiltrate sensitive authentication material.

Thought Process:
My initial approach involved searching for common credential dumping artifacts like .dmp files, or explicit mentions of "mimikatz" or "lsass" in filenames or command lines. However, these yielded no results. Realizing I might be overthinking, I simplified my search to focus on any filenames or command lines containing "mim." This broad yet targeted approach allowed me to discover the "mimidump_sim.txt" file, which, while a "simulation" in this scenario, directly indicates the adversary's interest in credential access. The hint "Possible Mimikatz variations" was crucial in guiding this simplified search.

Discovery: mimidump_sim.txt

Query Used:

```kusto
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"  // Replace with the second compromised host
| where FileName contains "mim" or ProcessCommandLine contains "mim"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp desc
```
###Flag 12 – Unusual Outbound Data Transfer
Objective: Investigate signs of potential data exfiltration or transfer to untrusted locations.

What was Hunted: External destinations indicative of third-party file storage or sharing services, and the associated process's SHA256 hash.

Analytical Insight: The ultimate goal of many intrusions is data exfiltration. Identifying outbound connections to suspicious external services, especially those not authorized for business use, is a critical indicator of data theft. The SHA256 hash of the initiating process provides a concrete IOC for future detection.

Discovery: 9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3

Query Used:

```kusto
DeviceNetworkEvents
| where RemoteUrl in ("eo1v1texxlrdq3v.m.pipedream.net", "eoqsu1hq6e9ulga.m.pipedream.net")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, RemoteUrl
| order by Timestamp desc
```
### Flag 13 – Sensitive Asset Interaction
Objective: Reveal whether any internal documents of significant value or sensitivity were accessed by the adversary.

What was Hunted: Access logs involving time-sensitive or project-critical files.

Analytical Insight: Adversaries often target specific types of documents that provide strategic advantage, financial gain, or competitive intelligence. Identifying access to such "crown jewel" data is paramount for assessing the full impact of the breach. The hint about "this year's end month projects (yyyy-mm)" provided a strong lead.

Thought Process:
My initial hunt for documents based on the yyyy-mm format (e.g., 2025-12.lnk) did not yield the correct answer, indicating that the adversary might not have strictly adhered to that naming convention or that the target was a different type of file. I then broadened my search to include common document extensions (.docx, .pdf, etc.) and terms like "RolloutPlan," "StrategicPlan," and "Employee Data." By focusing on distinct filenames from the results and applying the context of the hint, RolloutPlan_v8_477.docx emerged as the most suspicious and strategically valuable file for an adversary to target.

Discovery: RolloutPlan_v8_477.docx

Query Used:

```kusto
//to find 2025-12.lnk
DeviceFileEvents
| where DeviceName == "victor-disa-vm"
| where FileName endswith ".lnk" or FileName endswith ".docx" or FileName endswith ".pdf" or FileName endswith ".csv" or FileName endswith ".txt" or FileName endswith ".xml"
| where FileName contains_cs "RolloutPlan" or FileName contains_cs "StrategicPlan" or FileName contains_cs "2025"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, ActionType
| order by Timestamp desc
|distinct FileName,DeviceName,InitiatingProcessFileName, FolderPath
```
### Flag 14 – Tool Packaging Activity: Preparing for Movement
Objective: Spot behaviors related to preparing malicious code or scripts for movement or exfiltration.

What was Hunted: Instances of compression or packaging of local assets, particularly in non-administrative or public directories.

Analytical Insight: Before exfiltrating data or moving tools to another system, adversaries often package them into compressed archives (e.g., ZIP files) for easier transfer and to potentially bypass some security controls. This "packaging" activity is a strong precursor to further malicious actions.

Thought Process:
The flag explicitly asked for the command used to compress a malicious tool. This immediately directed my attention to the Compress-Archive cmdlet in PowerShell. I structured my query to look for PowerShell executions on victor-disa-vm that specifically included Compress-Archive in their ProcessCommandLine. This direct approach quickly revealed the command and the destination path of the compressed archive.

Discovery: "powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command Compress-Archive -Path "C:\Users\Public\dropzone_spicy" -DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip" -Force

Query Used:

```kusto
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "Compress-Archive"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```
### Flag 15 – Deployment Artifact Planted: Staged Payload
Objective: Verify whether staged payloads were successfully saved to disk, indicating readiness for execution or exfiltration.

What was Hunted: Unusual file drops, particularly compressed archives, in public or shared paths that are not typically used for legitimate software or data storage.

Analytical Insight: The presence of a staged payload, even if not yet executed, is a clear and imminent threat. It signifies that the adversary has prepared the next phase of their attack, whether it's further compromise, data exfiltration, or the deployment of ransomware. Leveraging information from the previous "packaging" activity (Flag 14) is key to this detection.

Thought Process:
Building directly upon the discovery in Flag 14, where the Compress-Archive command revealed the DestinationPath, the answer to this flag was implicitly contained within the previous finding. The prompt to identify the "malicious tool in question" was directly answered by the destination filename from the compression command.

Discovery: spicycore_loader_flag8.zip

Query Used:

```kusto
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "Compress-Archive"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```
## Conclusion and Recommendations
This threat hunt successfully mapped a multi-stage intrusion, demonstrating the adversary's intent to establish deep persistence and achieve data exfiltration. The identified tactics, techniques, and procedures (TTPs) highlight a sophisticated attacker who leverages native tools (PowerShell, WMI, Scheduled Tasks) and obfuscation to maintain stealth. The chronological analysis of events, from initial access on Acolyte756 to lateral movement and data staging on victor-disa-vm, provides a comprehensive understanding of the attack chain.

## Key Takeaways:

Reliance on Native Tools: The adversary heavily utilized PowerShell, indicating a "living off the land" approach to minimize the footprint of custom malware.
Layered Persistence: Multiple persistence mechanisms (Registry Run keys, Scheduled Tasks, WMI) were employed, showcasing the adversary's determination to maintain access.
Evasion Techniques: Obfuscated PowerShell commands and the use of legacy PowerShell versions underscore the adversary's efforts to evade traditional detections.
Targeted Data Acquisition: The focus on documents like RolloutPlan_v8_477.docx confirms the adversary's intent to acquire specific, high-value information.

## Recommendations for Enhanced Security Posture:

Enhanced PowerShell Logging and Monitoring: Implement Script Block Logging, Module Logging, and Transcription for all PowerShell activities. Centralize these logs for robust analysis and anomaly detection. Develop specific detection rules for encoded commands and downgraded PowerShell versions.
WMI Event Monitoring: Strengthen WMI event logging and actively monitor for suspicious WMI Permanent Event Consumers, Filters, and Bindings, especially those related to PowerShell execution.
Scheduled Task Monitoring: Implement granular logging for scheduled task creation, modification, and execution. Establish baselines for legitimate tasks and alert on deviations.
Registry Monitoring for Persistence: Continuously monitor common and uncommon registry run keys for unauthorized modifications or new entries, particularly those associated with scripting engines.
Outbound Network Traffic Analysis: Implement deep packet inspection and network flow analysis to detect anomalous outbound connections to unsanual or untrusted domains and IP addresses, especially those associated with cloud services like Pipedream.
Endpoint Detection and Response (EDR) Tuning: Review and fine-tune EDR rules to detect the specific TTPs observed, including suspicious file creations (e.g., savepoint_sync.ps1, mimidump_sim.txt, spicycore_loader_flag8.zip) and process command lines.
User Behavior Analytics (UBA): Leverage UBA solutions to identify unusual user activity, such as access to sensitive documents at atypical times or or from unexpected locations.
Regular Credential Hygiene Audits: Implement robust password policies, enforce multi-factor authentication (MFA) where possible, and regularly audit for credential reuse or weak local administrator passwords.
Threat Intelligence Integration: Continuously update threat intelligence feeds to include IOCs identified in this hunt and monitor for similar TTPs reported by other organizations.
This hunt has provided invaluable insights into the adversary's methodology. By implementing these recommendations, our organization can significantly improve its resilience against similar advanced persistent threats and reduce the risk of future compromises. Continuous proactive threat hunting, informed by intelligence and internal findings, remains crucial to staying ahead of evolving threats.
