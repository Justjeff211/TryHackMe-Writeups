# REvil Corp - Memory Forensics

## Scenario

An employee at Lockman Group reported that all their files had been renamed with an unfamiliar extension. IT confirmed ransomware and escalated to the Incident Response team. The investigation used **Redline** to analyse a memory image from the compromised machine.

----------

## What Is Memory Forensics?

Memory forensics is the analysis of a captured snapshot of a computer's RAM (Random Access Memory).

**Why RAM matters:** The disk stores files permanently. RAM stores what is actively happening; running processes, open network connections, loaded code, decrypted data and temporary artifacts that may never touch the disk.

**What memory analysis can reveal that disk analysis cannot:**

-   Malware that runs entirely in memory (fileless malware)
-   Decrypted versions of encrypted payloads
-   Active network connections at the time of capture
-   Injected code hidden inside legitimate processes
-   Credentials stored in memory by running applications

----------

## What Is Redline?

Redline is a free memory forensics tool by FireEye/Mandiant. It allows analysts to:

-   Review running processes and their associated files
-   Examine file system artifacts
-   Analyse timeline data
-   View browser history
-   Review network connection data
-   Search memory for strings and patterns

It provides a structured interface for navigating memory artifacts without requiring low-level forensic expertise.

----------

## Investigation Breakdown

### Step 1: Establishing System Context

Before looking for malicious activity, establish a baseline:

-   Who was logged in?
-   What operating system was running?
-   What is the normal environment for this machine?

**Why this matters:** Anomalies only make sense against a baseline. A process running from `AppData\Temp` is suspicious on a standard workstation but might be expected in a development environment.

----------

### Step 2: File Download History

Redline stores browser and application download history as an artifact.

**What was found:** A suspicious executable was downloaded from a raw IP address rather than a domain. This is a significant red flag because legitimate software distribution almost never uses raw IPs.

**The malicious binary:** `WinRAR2021.exe` - named to look like a legitimate software installer, a social engineering technique designed to trick users into executing it.

----------

### Step 3: Understanding File Hashes

A **file hash** is a fixed-length fingerprint generated from a file's contents using an algorithm (MD5, SHA1, SHA256).

**Properties:**

-   Same file always produces the same hash
-   Any change to the file produces a completely different hash
-   Two different files with the same hash is computationally near-impossible (for SHA256)

**How analysts use hashes:**

-   Submit to VirusTotal to check against known malware databases
-   Compare against known-good baselines
-   Share as IOCs to detect the same file across other systems

----------

### Step 4: Timeline Analysis

Redline's Timeline feature logs system events chronologically - file modifications, process creation, registry changes.

**How timeline analysis works:** You look for clusters of activity that occurred in a short time window following an execution event.

**From this investigation:** After the malicious binary executed, 48 files were renamed within a very short timeframe - all receiving the same unusual extension. This pattern is a definitive indicator of automated file encryption, which is the core behaviour of ransomware.

----------

### Step 5: Ransomware Artifacts

Ransomware typically leaves multiple artifacts beyond encrypted files:

**Ransom note:** A text file dropped in visible locations (Desktop, document folders) explaining the attack and providing payment instructions.

**Wallpaper change:** A common ransomware behaviour - the desktop background is replaced with a ransom demand image to ensure the victim immediately sees it.

**Hidden lock file:** A zero-byte file used by the ransomware to signal that the system has already been processed (prevents double-encryption).

All three were found during this investigation.

----------

### Step 6: Browser History as Evidence

Browser history revealed that the victim had visited an attacker-provided URL, likely found in the ransom note which appeared to be a decryption portal.

**Why this matters:** Browser history is often overlooked in investigations but it can reveal:

-   Initial phishing links
-   Malicious download sources
-   Attacker infrastructure (payment portals, C2 panels)

----------

### Step 7: Malware Attribution

With hashes extracted, they were submitted to **VirusTotal** - a platform that scans files against dozens of antivirus engines and provides community-sourced intelligence.

The scan returned matches identifying the malware as **REvil** (also known as **Sodinokibi** or **Sodin**) - a well-documented ransomware-as-a-service (RaaS) operation.

**RaaS explained:** Ransomware-as-a-Service is a model where the malware developers lease their tools to affiliates who conduct attacks. The developers take a percentage of ransom payments. This business model has made ransomware significantly more prevalent.

----------

## Key Takeaways

-   Memory forensics captures live attacker activity that disk analysis may miss
-   Timeline correlation is the core skill in ransomware investigations
-   File metadata (hashes, sizes, timestamps, extensions) tells the story
-   Browser artifacts are underutilized but highly valuable
-   Attribution requires external threat intelligence, not just local artifacts

----------

## SOC Analyst Reflection

As a SOC Analyst, my typical workflow involves monitoring alerts, triaging events and escalating incidents. This investigation showed what happens after escalation, how IR teams reconstruct the full story from evidence.

Understanding this process helps me:

-   Write better escalation notes (include relevant artifacts)
-   Ask the right questions during initial triage
-   Understand what evidence to preserve before containment

