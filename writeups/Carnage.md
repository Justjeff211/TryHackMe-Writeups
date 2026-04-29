# TryHackMe Writeup: Carnage

**Room:** Carnage  
**Difficulty:** Medium  
**Author:** Mojalefa Lawrence Letsoara (JustJeff211Cyber)  
**Tools Used:** Wireshark | TCP Stream Analysis 



----------

### Overview

This investigation analyses a packet capture (PCAP) file to identify malicious activity within a network. The goal is to reconstruct attacker behaviour from initial access through command-and-control communication using only network traffic.

Unlike endpoint investigations, this analysis relies entirely on understanding protocols such as HTTP, DNS and SMTP to identify indicators of compromise and attacker activity.

----------

### Environment Setup

The analysis was conducted on a Linux-based virtual machine provided by TryHackMe. The PCAP file (`carnage.pcap`) was located in the Analysis directory on the Desktop, ready for inspection in Wireshark.

https://github.com/user-attachments/assets/5c79074a-0ec2-4575-9904-87ee4d19d7da


----------

### Investigation

----------

### Phase 1: Initial Access – Malicious File Download

Filtering HTTP traffic in Wireshark revealed a GET request where the victim downloaded a ZIP archive from an external server:

```
GET /incidunt-consequatur/documents.zip HTTP/1.1
Host: attirenepal.com
```

To get the timestamp in the correct format, the time display was adjusted via View > Time Display Format > UTC Date and Time of Day.

https://github.com/user-attachments/assets/13e6c39b-b59e-4014-8234-5fb7ec0bb437

https://github.com/user-attachments/assets/ec665cb9-ad49-4e93-a9f2-5e057d625955

https://github.com/user-attachments/assets/82b1f5ad-3757-4745-8baf-a121953ffff8

The first HTTP connection to the malicious IP was recorded at:

```
2021-09-24 16:44:38
```

Attach Image

#### Analysis 

The initial compromise begins with the download of `documents.zip`, indicating a user-driven retrieval of a malicious file consistent with a phishing delivery method where a user clicks a link or opens an attachment.

Attackers commonly use compressed archives to:

-   Bypass email and web security filtering
-   Deliver staged payloads inside seemingly legitimate files
-   Conceal malicious content from casual inspection

Following the TCP stream of the GET request confirmed the archive contains an Excel file (`chart-1530076591.xls`), which is likely used to execute malicious code via macros. This is a well-established technique where the victim is prompted to click "Enable Content", triggering the embedded script.

The web server hosting the malicious file was identified from the HTTP response headers:

-   **Server:** LiteSpeed
-   **X-Powered-By:** PHP/7.2.34

This marks the **initial access point**, where the attacker successfully introduces malware into the environment.

----------

### Phase 2: TLS Handshake – Hidden Infrastructure Discovery

Following the initial download, the infected host begins initiating TLS connections. Rather than inspecting encrypted payloads directly, the investigation focused on TLS Client Hello messages, which expose the Server Name Indication (SNI) field, revealing destination domains before encryption is established.

The following filter was applied with a narrow time window aligned to the infection period:

```
tls.handshake.type == 1 and (frame.time >= "2021-09-24 16:45:11") && (frame.time <= "2021-09-24 16:45:30")
```

This returned five packets, from which three suspicious domains were identified:

-   `finejewels.com.au`
-   `thietbiagt.com`
-   `new.americold.com`

#### Analysis

Multiple domains contacted in a short window shortly after execution indicate redundant or staged attacker infrastructure. This is consistent with malware attempting to establish reliable communication channels, where fallback domains are used if the primary fails.

Inspecting the TLS certificate for the first domain (`finejewels.com.au`) via the handshake packets revealed:

-   **Certificate Authority:** GoDaddy Secure Certificate Authority (G2)

The use of a legitimate CA is deliberate, it allows malicious traffic to blend with normal HTTPS activity and reduces the likelihood of detection by security tools.

----------

### Phase 3: Command and Control (C2) – Cobalt Strike Identification

To identify active C2 infrastructure, HTTP GET traffic was filtered and the Wireshark Conversations view (Statistics > Conversations) was used to identify IP addresses with high-frequency communication.

These IPs were then verified against VirusTotal (Community tab), confirming two Cobalt Strike C2 servers:

-   `185.106.96.158`
-   `185.125.204.174`

Further inspection revealed the associated infrastructure for each:

**First C2 IP (185.106.96.158):**

-   Host header: `ocsp.verisign.com`
-   Domain: `survmeter.live`

**Second C2 IP (185.125.204.174):**

-   Domain: `securitybusinpuff.com`

#### Analysis 

The presence of Cobalt Strike confirms the attack has progressed well beyond initial infection into active post-exploitation. Cobalt Strike is a professional-grade framework used for:

-   Remote command execution
-   Persistence
-   Lateral movement
-   Data exfiltration

The use of `ocsp.verisign.com` as a host header is a deliberate evasion technique, it mimics a legitimate certificate validation service to disguise C2 traffic as normal HTTPS activity. At this stage the system is no longer just infected; it is actively controlled by the attacker.

----------

### Phase 4: Post-Infection Beaconing – HTTP POST Traffic

To investigate how the compromised host communicated after infection, POST requests were filtered:

```
http.request.method == "POST"
```

Following the TCP stream of the first POST packet revealed:

-   **Destination domain:** `maldivehost.net`
-   **First 11 characters sent:** `zLIisQRWZI9`
-   **First packet length:** `281` bytes
-   **Server header:** `Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4`


#### Analysis (Why This Matters)

POST requests represent data being sent **from the victim to the attacker** — the opposite direction of a normal download. This behaviour is characteristic of beaconing, where:

-   The compromised host periodically checks in with the C2 server
-   Encoded or obfuscated data is transmitted outbound
-   The server responds with instructions for the next action

The encoded URI structure (`/zLIisQRWZI9/`) is consistent with Cobalt Strike beacon profiles, which use randomised paths to avoid pattern-based detection. The presence of cPanel in the server header suggests the attacker is leveraging a compromised shared hosting server rather than dedicated infrastructure which is a common cost-reduction tactic.

----------

### Phase 5: DNS Activity – Victim Profiling

DNS traffic was filtered to identify host profiling behaviour:

```
dns && frame contains "api"
```

This revealed a DNS query to an external IP-checking service:

-   **Domain:** `api.ipify.org`
-   **Timestamp:** `2021-09-24 17:00:04 UTC`

#### Analysis

This service returns the system's public IP address. Malware routinely performs this check to:

-   Identify the victim's geographic location
-   Detect sandbox or analysis environments (which often have unusual IP ranges)
-   Determine whether to continue exploitation or remain dormant

This step represents **attacker reconnaissance after compromise** — the malware profiling the victim before proceeding with further operations.

----------

### Phase 6: SMTP Activity – Post-Compromise Abuse

SMTP traffic was analysed using:

```
frame contains "MAIL FROM"
```

This identified the first sender address involved in outbound email activity:

-   **MAIL FROM:** `farshin@mailfa.com`

Filtering for `smtp` alone confirmed the total volume of email-related traffic:

-   **Total SMTP packets:** `1439`

#### Analysis
SMTP activity originating from a compromised host indicates the attacker is using the system for secondary malicious operations such as:

-   Spam distribution
-   Phishing campaigns targeting additional victims
-   Botnet participation

The high packet volume confirms this is automated behaviour, not manual activity. The compromise is no longer isolated to a single machine, the infected host is now part of a **broader malicious infrastructure**, actively contributing to the attacker's wider operations.

----------

### Indicators of Compromise (IOCs)

#### IP Addresses

-   185.106.96.158
-   185.125.204.174

#### Domains

-   attirenepal.com
-   finejewels.com.au
-   thietbiagt.com
-   new.americold.com
-   survmeter.live
-   securitybusinpuff.com
-   maldivehost.net
-   api.ipify.org

#### File Artifacts

-   documents.zip
-   chart-1530076591.xls

#### Email

-   [farshin@mailfa.com](mailto:farshin@mailfa.com)

----------

### Attack Chain Summary

```
User downloads malicious ZIP (documents.zip) from attirenepal.com
        ↓
Excel macro payload (chart-1530076591.xls) executes
        ↓
TLS connections to finejewels.com.au, thietbiagt.com, new.americold.com
        ↓
Cobalt Strike C2 established (185.106.96.158, 185.125.204.174)
        ↓
Active beaconing via HTTP POST to maldivehost.net
        ↓
Victim profiled via DNS query to api.ipify.org
        ↓
Host used for SMTP malspam activity
```

----------

| Technique | Name | Tactic |
|-----------|------|--------|
| T1105 | Ingress Tool Transfer | Initial Access |
| T1566 | Phishing | Initial Access |
| T1071 | Application Layer Protocol | Command and Control |
| T1071.001 | Web Protocols (HTTP/S) | Command and Control |
| T1055 | Process Injection (likely) | Defense Evasion |
| T1016 | System Network Configuration Discovery | Discovery |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |

----------

### Conclusion

This investigation confirms a complete compromise lifecycle - from phishing delivery through active command-and-control and post-compromise abuse of the host.

The attacker demonstrated deliberate tradecraft throughout:

-   Legitimate TLS certificates to blend with normal traffic
-   Cobalt Strike for professional post-exploitation capability
-   Trusted-looking host headers to disguise C2 communication
-   Compromised shared hosting infrastructure to reduce attribution risk

https://github.com/user-attachments/assets/347e303a-4df7-49c4-9706-448c04922e89

----------

### Final Note

This write-up focuses on understanding attacker behaviour through network traffic rather than simply extracting answers.

The goal is to develop the ability to:

-   Recognise malicious patterns
-   Understand attack progression
-   Apply analysis in real-world SOC environments
