# Dunkle Materie - Ransomware Investigation

## Scenario

The SOC received a firewall alert indicating that a machine in the Sales department was communicating with suspicious external domains. Analysts discovered that base64-encoded data was being sent outbound. Upon investigation, the machine showed clear signs of a ransomware infection.

The investigation used **ProcDOT**, a behavioural analysis tool that correlates Procmon logs and PCAP network captures into a single interactive graph.

----------

## What Is ProcDOT?

ProcDOT is a visualization tool that takes two data sources:

1.  **Procmon CSV** - a log of all process activity on the host (file reads, writes, registry changes, network events)
2.  **PCAP file** - captured network traffic

It combines them into an animated, interactive graph showing exactly which process caused which network connection, registry change, or file operation.

**Why this is powerful:** Raw Procmon logs contain thousands of events. It is nearly impossible to manually correlate them with network traffic. ProcDOT does this automatically, letting analysts focus on behaviour rather than parsing.

----------

## Key Concept: Process Lineage

Every action on a Windows system is performed by a process. Understanding **which process did what** - and more importantly, **which process started it** - is the foundation of host-based forensics.

**Process lineage** refers to the parent-child relationship between processes.

**Example:**

```
explorer.exe
  └── malicious.exe
        ├── cmd.exe
        └── powershell.exe
```

This chain answers: "How did the attacker get code running on the system?"

**Key red flag from this investigation:** A process named `exploreer.exe` was identified — note the deliberate misspelling. This is a technique called **masquerading**, where malware names itself similarly to a legitimate Windows process (`explorer.exe`) to avoid detection at first glance.

----------

## Masquerading Explained

Masquerading is a technique under **MITRE ATT&CK T1036**. Attackers rename malicious executables to look like:

-   System processes (`svchost.exe`, `explorer.exe`, `lsass.exe`)
-   Legitimate software (`chrome.exe`, `update.exe`)

**How to detect it:**

-   Check the full file path - legitimate system processes run from specific directories (e.g., `C:\Windows\System32`)
-   Check the parent process - legitimate system processes have expected parents
-   Verify the hash against known-good baselines

In this case, `exploreer.exe` was executing from:

```
C:\Users\sales\AppData\Local\Temp\exploreer.exe
```

A legitimate `explorer.exe` would never run from a user's Temp directory.

----------

## Command and Control (C2) Communication

After execution, the malware communicated with external servers. This is called **Command and Control (C2)** communication.

**What C2 is used for:**

-   Receiving instructions from the attacker
-   Sending stolen data outbound (exfiltration)
-   Confirming successful infection
-   Receiving encryption keys (in ransomware)

**What analysts look for:**

-   HTTP POST requests (data being sent out)
-   Unusual or newly registered domains
-   Connections from unexpected processes
-   Encoded or encrypted payloads

**From this investigation:** Two suspicious domains were identified in the network traffic. They were validated using **VirusTotal**, which confirmed both were associated with malicious activity. A third domain appeared (cisco.com) - this was a **Cisco Umbrella** block page, indicating the security infrastructure attempted to block the connection and returned an HTTP 403 response.

----------

## Registry Modifications (Persistence and System Changes)

The Windows Registry is a database storing configuration settings for the operating system and applications.

Malware commonly modifies the registry to:

-   **Persist across reboots** - by adding entries that run the malware on startup
-   **Change system behaviour** - such as disabling security tools
-   **Store configuration** - including encryption parameters

**From this investigation:** Registry entries were found related to:

-   **Wallpaper modification** - ransomware changed the desktop background to display a ransom demand. The path to the bitmap file was stored in `HKEY_CURRENT_USER\Control Panel\Desktop`
-   **Drive mounting** - a drive was mounted and assigned the letter `Z:`, with evidence stored under `HKLM\SYSTEM\MountedDevices\DosDevices\Z:`

----------

## Data Exfiltration via HTTP POST

The malware sent system information and encryption results to the C2 servers using HTTP POST requests.

**HTTP POST** is a method typically used to submit data. In normal use, it submits form data to websites. In malware, it sends stolen information to attacker infrastructure.

**What was observed:**

-   POST requests to the identified C2 domains
-   Encoded data in the request body
-   A specific user-agent string in the HTTP headers

**User-agent strings** identify the software making the HTTP request. Malware often uses fake or outdated user-agent strings to blend in. The user-agent extracted from the traffic in this investigation was: `Firefox/89.0`.

----------

## Attribution and Threat Intelligence

After collecting IOCs (domains, IPs, behavioural indicators), the final step was attribution - identifying the ransomware family.

**How attribution works:**

1.  Search collected IOCs (domains, hashes, file names) in threat intelligence platforms
2.  Cross-reference with published research and malware reports
3.  Match behavioral patterns to known ransomware families

The domains identified during this investigation were associated with **BlackMatter ransomware** - confirmed through external research and threat intelligence sources.

----------

## Key Takeaways

-   Visualisation tools like ProcDOT dramatically reduce analysis time by correlating multiple data sources
-   Process lineage is the starting point for any host-based investigation
-   Network traffic tied to specific processes reveals C2 behaviour
-   Registry changes reveal persistence and system manipulation
-   Threat intelligence platforms turn raw IOCs into attribution

----------

## SOC Analyst Reflection

This investigation closely mirrors real SOC escalation workflows:

A firewall alert > analyst investigates > discovers data exfiltration > identifies malware behaviour > extracts IOCs > attributes to known threat actor.

The skills reinforced here - correlating events across data sources, identifying anomalous process behaviour, validating network indicators are directly applicable to daily SOC work.

----------
