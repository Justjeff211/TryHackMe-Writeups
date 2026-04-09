TryHackMe - Brim: Network Traffic Investigation

**Difficulty:** Medium  
**Category:** Network Forensics / Threat Hunting  
**Tool:** Brim 

---

## Overview

Three machines in the Finance department at Pfeffer PLC were compromised through 
a phishing attempt and an infected USB drive. The Incident Response team captured 
network traffic logs from all three endpoints.

This investigation uses **Brim** to analyse three separate PCAPs, identify malicious 
activity, extract indicators of compromise, and attribute the attacks to known 
malware families.

---

## What Is Brim?

Brim is a network traffic analysis tool that combines the power of:
- **Zeek** - a network analysis framework that generates structured logs from PCAPs
- **Suricata** - an intrusion detection engine that generates alerts
- **Zed Query Language (ZQL)** - a query language for filtering and analysing logs

**Why Brim matters in SOC/IR:**  
Raw PCAPs are difficult to work with at scale. Brim converts network traffic into 
structured, queryable logs, making it fast to identify suspicious connections, 
extract IOCs, and correlate events across multiple data sources without manually 
reading packet data.

---

## Key Concepts

---

### Zeek Log Types

Brim uses Zeek to parse PCAPs into structured log types:

| Log Type | What It Contains |
|----------|-----------------|
| `conn` | All network connections (src/dst IP, bytes, duration) |
| `http` | HTTP requests (host, URI, method, status code, response size) |
| `dns` | DNS queries and responses |
| `files` | Files transferred over the network |

Understanding which log type to query is the foundation of efficient network 
forensics.

---

### Zed Query Language (ZQL)

ZQL allows analysts to filter, cut, sort and aggregate log data quickly.

**Common patterns used in this investigation:**

Filter by log type:
_path=="http"

Cut specific fields:
_path=="http" | cut id.orig_h, id.resp_h, host, uri

Filter by status code:
_path=="http" | status_code == 404

Count unique values:
_path=="dns" | count() by query | sort -r

Sum totals:
_path=="dns" | count() by query | sort -r count | sum(count)

---

### Suricata Alerts

Suricata is an intrusion detection system (IDS) that inspects network traffic 
against known threat signatures.

**Query Suricata alerts in Brim:**
event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip

Alert categories like **"A Network Trojan was detected"** indicate Suricata matched 
traffic against a known malware signature, a high-confidence indicator of compromise.

---

### C2 (Command and Control) Communication

After initial infection, malware typically establishes a C2 channel to:
- Receive instructions from the attacker
- Send stolen data outbound
- Download additional payloads

**In network traffic, C2 often appears as:**
- HTTP POST requests to suspicious domains
- Repeated DNS queries to unusual domains
- Executable file downloads (`.exe`, `.dll`)
- Beaconing - regular, repeated connections at fixed intervals

---

## Investigation 1 - Infection1.pcap

### Victim IP
Used the **Unique Network Connections** query to identify the internal machine 
generating suspicious traffic.

**Victim:** `192.168.75.249`

https://github.com/user-attachments/assets/c50f0068-42b8-4a60-9e25-0616186f4916
https://github.com/user-attachments/assets/b7063503-48f5-40ca-ae2f-e1893857e4ac


---

### HTTP 404 Requests - Suspicious Domains

Filtered HTTP requests by status code 404 to find failed connection attempts 
to suspicious domains - often indicating malware trying to reach C2 infrastructure 
that is temporarily unavailable.
_path=="http" | status_code == 404 | cut id.orig_h, id.resp_p, id.resp_h, host, uri | uniq -c

**Domains contacted:**  
`cambiasuhistoria.growlab.es`, `www.letscompareonline.com`

---

### Successful HTTP Connection

Filtered for HTTP 200 responses and sorted by `response_body_len` to find a 
successful connection where data was received from the server.
_path=="http" | status_code == 200 | cut id.orig_h, id.resp_h, id.resp_p, response_body_len

**Domain:** `ww25.gocphongthe.com`  
**Destination IP:** `199.59.242.153`  
**Response body length:** `1,309`

https://github.com/user-attachments/assets/dccd1ba6-cf2e-41f2-97ad-1514191be036


---

### DNS Query Analysis

Queried unique DNS requests to identify how many times the malware attempted 
to resolve a specific C2 domain.
_path=="dns" | count() by query | sort -r

**Domain:** `cab.myfkn.com`  
**Unique DNS requests:** `7`

Repeated DNS queries to a single domain indicate beaconing behaviour, the malware 
repeatedly checking in with its C2 infrastructure.

---

### URI Analysis

Filtered HTTP requests to identify the specific URI path used when communicating 
with a known malicious domain.
_path=="http" | cut id.orig_h, id.resp_p, id.resp_h, host, uri | uniq -c

**Domain:** `bhaktivrind.com`  
**URI:** `/cgi-bin/JBbb8/`

URI paths like `/cgi-bin/` are commonly used by malware for C2 communication 
as they mimic legitimate web server paths.

---

### Malicious Executable Download

Identified an executable file downloaded over HTTP which is a key indicator of a 
secondary payload being delivered post-infection.

**Malicious server IP:** `185.239.243.112`  
**Executable downloaded:** `catz.exe`

---

### Malware Attribution

The 404 domains were submitted to **VirusTotal** for reputation analysis. 
The community tags confirmed the malware family.

**Malware family:** `Emotet`

**What is Emotet?**  
Emotet is a modular banking trojan that evolved into a full malware delivery 
platform. It spreads via phishing emails, establishes persistence and 
downloads secondary payloads. It was one of the most prolific malware 
families before its infrastructure takedown in 2021.

---

## Investigation 2 - Infection2.pcap

### Victim IP
Used the **Connection Received Data** query to identify the machine generating 
the most outbound traffic.
_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes

**Victim:** `192.168.75.146`

---

### HTTP POST Connections

HTTP POST requests are used to send data from client to server. In malware 
context, POST requests often indicate data exfiltration or C2 check-ins.
method=="POST" | cut ts, uid, id, method, uri, status_code

**C2 IP:** `5.181.156.252`  
**Number of POST connections:** `3`

---

### Binary Download

Identified the domain and full URI path used to deliver a malicious executable 
to the victim machine.
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c

**Domain:** `hypercustom.top`  
**Binary URI:** `/jollion/apines.exe`  
**Hosting IP:** `45.95.203.28`

---

### Suricata Alerts

Queried Suricata alerts to identify high-confidence malware detections within 
the traffic.
event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip

**Alert:** A Network Trojan was detected  
**Source:** `192.168.75.146` → **Destination:** `45.95.203.28`

---

### Malware Attribution

Submitted the `.top` domain to **URLhaus Database** to identify the malware family.

**Malware:** `Redline Stealer`

**What is Redline Stealer?**  
Redline Stealer is an information-stealing malware sold as a service on criminal 
forums. It harvests:
- Browser credentials and cookies
- Cryptocurrency wallet data
- System information
- FTP and VPN credentials

It communicates results back to the attacker via HTTP POST requests - consistent 
with what was observed in this traffic capture.

---

## Investigation 3 - Infection3.pcap

### Victim IP
_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes

**Victim:** `192.168.75.232`

---

### C2 Domains - Binary Downloads

Filtered HTTP requests ordered by timestamp to identify domains delivering 
binaries in chronological order.
_path=="http" | cut ts, id.orig_h, id.resp_h, id.resp_p, method, status_code, host, uri | uniq -c | sort ts

**C2 Domains (earliest to latest):**
1. `efhoahegue.ru` → IP: `162.217.98.146`
2. `efhoahegue.ru` → IP: `199.21.76.77`
3. `xfhoahegue.ru` → IP: `63.251.106.25`

Note the slight domain variation between `efhoahegue.ru` and `xfhoahegue.ru` — 
a technique called **typosquatting** used to diversify C2 infrastructure and 
evade domain-based blocking.

---

### DNS Query Count

Counted unique DNS queries to the first C2 domain to understand how frequently 
the malware was attempting to resolve it.
_path=="dns" | count() by query | sort -r

**Unique DNS queries to efhoahegue.ru:** `2`

---

### Binary Download Count

Identified how many separate executables were downloaded from the primary C2 domain.
_path=="http" | efhoahegue.ru | cut ts, uri | uniq -c | sort ts

**Binaries downloaded:** `5`

---

### User Agent Analysis

Extracted the user-agent string used during binary downloads. Malware often 
uses outdated or spoofed user-agents to blend in with legitimate traffic or 
evade basic detection rules.
_path=="http" | efhoahegue.ru | cut ts, uri, user_agent | uniq -c | sort ts

**User-Agent:**  
`Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0`

This is Firefox 25.0 from 2013 — an extremely outdated browser version that 
no legitimate user would realistically be running, making it a clear anomaly.

---

### Total DNS Connection Count

Summed all DNS query counts to determine total DNS activity in the capture.
_path=="dns" | count() by query | sort -r count | sum(count)

**Total DNS connections:** `986`

---

### Malware Attribution

Searched for the C2 domain using OSINT (Google search with quotes, excluding 
the `.ru` TLD to avoid direct interaction).

**Malware:** `Phorpiex` (also known as Trik)

**What is Phorpiex?**  
Phorpiex is a worm that spreads via:
- Removable USB drives
- Spam campaigns
- Downloading and executing additional payloads

It is known for maintaining large botnets and delivering secondary malware 
including ransomware and cryptocurrency miners. The USB infection vector 
mentioned in the scenario is consistent with Phorpiex's known spreading methods.

---

## Skills Demonstrated

- Network traffic analysis using Brim and ZQL
- HTTP, DNS, and connection log analysis
- C2 infrastructure identification
- Executable download detection
- Suricata alert analysis
- Malware attribution using VirusTotal and URLhaus
- OSINT-based threat intelligence

---

## Key Lessons Learned

1. **Structured logs are faster than raw PCAPs** - Brim's Zeek integration 
   makes large captures queryable in seconds
2. **HTTP POST requests are a primary C2 signal** - always investigate 
   outbound POST traffic to unknown destinations
3. **DNS beaconing reveals persistent malware** - repeated queries to a 
   single domain indicate active C2 communication
4. **User-agent strings can expose malware** - outdated or inconsistent 
   user-agents are a reliable anomaly signal
5. **Multiple data sources confirm findings** - combining Zeek logs, 
   Suricata alerts, and external threat intel gives high-confidence attribution
6. **Domain variations indicate infrastructure diversity** - slight spelling 
   changes across C2 domains are intentional evasion techniques

---

## Conclusion

This investigation covered three separate infections across a corporate network, 
each involving different malware families and delivery mechanisms. Using Brim's 
query capabilities, it was possible to quickly pivot between connection data, 
HTTP requests, DNS queries, and IDS alerts to build a complete picture of each 
compromise.

From a SOC perspective, the techniques used here - filtering for 404s, tracking 
POST requests, counting DNS queries, and extracting executables from HTTP logs - 
are directly applicable to daily threat hunting and alert triage workflows.
