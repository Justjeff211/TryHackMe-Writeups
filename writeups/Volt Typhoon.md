# TryHackMe - Volt Typhoon IR Scenario
https://github.com/user-attachments/assets/1a7e2915-63a7-4c82-8727-cf3676b8e064

**Difficulty:** Medium  
**Category:** SOC / Incident Response (DFIR)  
**Tools:** Splunk | CyberChef

----------

## Overview

This investigation focuses on analysing logs within Splunk to reconstruct an intrusion attributed to the APT group Volt Typhoon.

The scenario simulates a real-world SOC investigation where an attacker gains initial access, escalates privileges, moves laterally and attempts to cover their tracks. The task is to follow the attacker’s activity across multiple log sources and build a clear timeline of events.

The objective was to:

-   Identify the initial point of compromise.
    
-   Track attacker activity across systems.
    
-   Detect privilege escalation and persistence mechanisms.
    
-   Analyse command execution and credential access techniques.
    
-   Trace lateral movement across hosts.
    
-   Identify data collection and staging activity.
    
-   Detect command-and-control (C2) setup.
    
-   Observe cleanup and anti-forensic behaviour.
    

----------

## About Volt Typhoon

Volt Typhoon is a state-aligned threat actor known for targeting critical infrastructure and high-value organizations. Their operations emphasise stealth and persistence.

Key characteristics:

-   Heavy use of **living-off-the-land binaries (LOLBins)** such as WMIC, PowerShell and netsh.
    
-   Minimal malware footprint, relying on built-in tools.
    
-   Strong focus on **credential access and lateral movement**.
    
-   Use of **web shells** for persistence.
    
-   Active **log clearing and artifact removal** to evade detection.
    

----------

## Initial Access – ADSelfService Plus Logs

The investigation begins with ADSelfService Plus logs, where the attacker exploited a vulnerability to gain access.

The first step was identifying suspicious password-related activity tied to a privileged account. By filtering for password change events, it became possible to isolate the moment the account was taken over.

https://github.com/user-attachments/assets/dc31d46e-41ae-4b31-8a5c-cb5648eb26bc

https://github.com/user-attachments/assets/3b7c2cd3-ebdc-48f7-affb-8a72e0aefc20

https://github.com/user-attachments/assets/bf35585f-e7e2-43be-8751-8890c8720d90

https://github.com/user-attachments/assets/f471ba6b-9be3-4dfc-a457-0eef880bc359

https://github.com/user-attachments/assets/799e6825-5197-4a70-ac39-ebb07a824515

```spl
index=main sourcetype=adss action_name="Password Change" username="dean-admin"

```

Once the compromise point was identified, the next step was pivoting on the timeline. Shortly after the takeover, additional administrative activity appeared, indicating that the attacker created a new privileged account.

To find this, enrollment and account setup actions were analysed:

```spl
index=main sourcetype=adss action_name="Security Question Setup" status=completed

```

**Key takeaway:** Initial access is rarely isolated. Attackers move quickly to establish control and persistence once credentials are obtained.

----------

## Execution – WMIC Activity

Volt Typhoon relies heavily on WMIC for remote execution and reconnaissance.

To investigate execution activity, WMIC logs were filtered for commands run under the compromised account. This revealed command-line activity used to enumerate system resources across multiple servers.

https://github.com/user-attachments/assets/0fe66cbb-ad83-49c0-8121-ed2789965c17

```spl
index=main sourcetype=wmic username="dean-admin"
| table _time, ip_address, command

```

Further analysis highlighted the use of uncommon commands, including database-related operations. To surface these, a rarity-based query was used:

```spl
index=main sourcetype=wmic username="dean-admin"
| rare limit=20 command

```

This helped identify actions associated with Active Directory database access and staging.

**Key takeaway:** Attackers often blend in using legitimate tools. Detection relies on identifying unusual usage patterns rather than malicious binaries.

----------

## Persistence – Web Shell Deployment

Persistence was achieved through the creation of a web shell.

Initially, there were no obvious indicators in the logs. Based on known Volt Typhoon techniques, research into commonly used web shell names provided useful pivots. Using these as search indicators led to identifying file creation activity on the compromised host.

```spl
index=main sourcetype=wmic username="dean-admin" ip_address="192.168.1.153"

```

This revealed the directory where the web shell was placed.

**Key takeaway:** Threat intelligence can guide investigations when direct evidence is not immediately visible.

----------

## Defense Evasion – Artifact Removal

After establishing persistence, the attacker began covering their tracks.

PowerShell logs were analysed for commands related to deletion and system modification. This revealed activity targeting RDP history and other artifacts.

```spl
index=* sourcetype=powershell host=volthunter
| table _time, CommandLine
| sort -_time

```

To track file manipulation, WMIC logs were reviewed in chronological order. This exposed file renaming activity used to disguise previously created archives.

```spl
index=* sourcetype=wmic username="dean-admin"
| table _time, ip_address, command
| sort _time

```

Additionally, registry queries were examined to identify checks for virtualised environments, which is a common anti-analysis technique.

**Key takeaway:** Defense evasion often includes both artifact removal and environmental awareness checks.

----------

## Credential Access – Registry and Memory Techniques

The attacker searched for stored credentials using registry queries.

```spl
index=* sourcetype=powershell "reg query"

```

This revealed multiple applications being targeted for credential harvesting.

Further analysis uncovered an encoded PowerShell command used to download and execute a credential dumping tool. Because the command was obfuscated, it required decoding outside of Splunk to fully understand its behaviour.

**Key takeaway:** Encoded PowerShell is a strong indicator of malicious intent and often hides credential dumping or payload execution.

----------

## Discovery & Lateral Movement

To understand the environment, the attacker enumerated Windows event logs.

https://github.com/user-attachments/assets/6cb80674-68c8-43d8-8434-608b0a38c76c

```spl
index=* sourcetype=powershell CommandLine=wevtutil

```

This revealed targeted log queries related to authentication events.

For lateral movement, file transfer activity was analysed using PowerShell copy operations:

```spl
sourcetype=powershell CommandLine=Copy-item

```

This showed me the movement of tools and web shells between systems, confirming expansion beyond the initial host.

**Key takeaway:** Lateral movement is often quiet and relies on legitimate administrative actions.

----------

## Collection – Data Staging

During the collection phase, the attacker identified and copied sensitive files.

```spl
sourcetype=powershell CommandLine=Copy-item

```

This revealed multiple structured data files being staged, likely for exfiltration.

**Key takeaway:** Data collection often appears as normal file operations. Context and timing are critical for detection.

----------

## Command & Control (C2) and Cleanup

The attacker established a communication channel using native networking tools.

```spl
index=* sourcetype=wmic "netsh"

```

This revealed proxy configuration activity consistent with C2 setup.

Finally, log clearing activity was identified:

```spl
sourcetype=powershell CommandLine=wevtutil

```

This showed multiple event logs being cleared to remove evidence of the intrusion.

**Key takeaway:** Cleanup is a strong indicator that the attacker has completed their objectives and is attempting to disappear.

----------

## Skills Demonstrated

-   Splunk log analysis and query building.
    
-   Timeline reconstruction of attacker activity.
    
-   Detection of living-off-the-land techniques.
    
-   Identification of persistence mechanisms.
    
-   Analysis of PowerShell and WMIC activity.
    
-   Detection of credential access techniques.
    
-   Tracking lateral movement across hosts.
    
-   Identifying data collection and staging behaviour.
   
-   Recognising defense evasion and cleanup techniques.
    

----------

## Key Lessons Learned

1.  **Attackers move fast after initial access.** Privilege escalation and persistence often occur within minutes.
    
2.  **LOLBins are difficult to detect.** Tools like WMIC and PowerShell are legitimate, making behavioural analysis essential.
    
3.  **Threat intelligence is valuable.** When logs don’t provide clear answers, known attacker techniques can guide investigation.
    
4.  **Encoded commands require extra effort.** Decoding PowerShell payloads is often necessary to understand attacker intent.
    
5.  **Log correlation is everything.** No single log tells the full story, multiple sources must be combined.
    
6.  **Cleanup is part of the attack.** Log deletion and artifact removal are deliberate and should be treated as high-confidence indicators.
    

----------

## Conclusion
https://github.com/user-attachments/assets/0cdf2d4b-c538-4ccb-9da6-23f2c9c41adc

This investigation demonstrates how a structured, log-driven approach can uncover the full lifecycle of an advanced attack.

Volt Typhoon’s reliance on legitimate tools highlights the importance of behavioural analysis over signature-based detection. By correlating events across multiple sources and maintaining a clear timeline, it is possible to reconstruct attacker activity even in environments with limited visibility.

From a SOC perspective, this reflects the transition from alert triage to full incident reconstruction, where understanding attacker behaviour becomes more important than simply identifying indicators.
