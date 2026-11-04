# Forensic Report: Case 001 — The Stolen Szechuan Sauce

## 1. Case profile

- **Dataset owner:** DFIR Madness
- **Investigation type:** Academic team exercise
- **Investigators:** Cassandra Dsouza and Hamzah Al-Nasser
- **Program:** Lighthouse Labs Cyber Security Immersive
- **Date completed:** January 2025
- **Primary systems:** Windows desktop and DC01/domain controller
- **Primary evidence:** E01 disk images, desktop memory, autoruns, Windows registry artifacts, and Case001 PCAP

## 2. Executive summary

The team examined the public DFIR Madness Case 001 artifacts to determine how the Windows environment was accessed, whether malware was present, how persistence was established, and what external infrastructure appeared in the evidence.

The investigation identified coreupdater.exe under C:\Windows\System32 and registry evidence consistent with persistence. Repeated RDP-related traffic was associated with 194.61.24.102, while memory and packet evidence associated suspicious activity with 203.78.103.109. The team also identified the operating systems and examined network, registry, and timeline information across the desktop and server workstreams.

The evidence supports unauthorized activity and malware persistence in the training scenario. Claims about data exfiltration and some malware capabilities remain hypotheses unless supported by a specific artifact. This public version separates observed evidence from inference.

## 3. Team contribution model

### Cassandra Dsouza

Cassandra completed the uncoloured/DC01-focused workstream in the source report:

- loaded and examined the DC01 E01 image;
- identified the server operating system;
- extracted and examined relevant server registry material;
- analyzed server time-zone and TCP/IP configuration;
- reviewed RDP-related network traffic;
- investigated the suspected initial-access source;
- identified and examined coreupdater.exe in server artifacts;
- documented findings and supporting screenshots; and
- contributed the methodology, integrated findings, and conclusion.

### Hamzah Al-Nasser

Hamzah completed the purple desktop-focused workstream:

- analyzed the desktop memory image;
- examined the desktop E01 image and registry hives;
- reviewed desktop-related PCAP evidence;
- investigated the process, file, and persistence evidence for coreupdater.exe;
- enriched file and IP indicators with VirusTotal;
- confirmed desktop operating-system details; and
- assessed observed and possible malware capabilities.

The final report combines the two workstreams and is credited jointly.

## 4. Methodology

### 4.1 Preserve and identify the supplied artifacts

The team worked from artifacts supplied with the public training case. A live investigation would also record acquisition metadata, hashes, custody transfers, original-media handling, and working-copy creation.

### 4.2 Establish system context

Disk and registry artifacts were used to identify operating systems, time-zone configuration, network configuration, filesystem paths, and system context.

### 4.3 Examine persistence and malware-related evidence

The team searched disk, memory, registry, and autoruns evidence for coreupdater.exe, its path, metadata, execution context, and persistence mechanisms.

### 4.4 Analyze network evidence

The Case001 PCAP was reviewed for RDP-related traffic, repeated connection patterns, external IP addresses, possible callbacks, and relationships between traffic and host artifacts.

### 4.5 Enrich indicators

File hashes and IP addresses were checked using VirusTotal. Reputation results were treated as enrichment, not a replacement for primary forensic evidence.

### 4.6 Correlate and qualify findings

Evidence from both workstreams was classified as:

- **Observed:** directly supported by an artifact;
- **Corroborated:** supported by multiple independent artifacts;
- **Inferred:** a reasonable interpretation requiring additional evidence; or
- **Unconfirmed:** discussed in the source report but not established by the portfolio evidence.

## 5. Evidence examined

| Artifact | Analysis purpose |
|---|---|
| DC01 E01 | Server OS, filesystem, registry, network configuration, malware-related files |
| Desktop E01 | Desktop filesystem, registry hives, malware path and metadata |
| Desktop memory | Processes, strings, possible network activity, malware references |
| Desktop autoruns | Startup and persistence evidence |
| Case001 PCAP | RDP patterns and communication with external IP addresses |
| SYSTEM and SOFTWARE hives | OS, time-zone, TCP/IP, service, and startup configuration |
| VirusTotal results | Historical reputation context for hashes and IP addresses |

## 6. Findings

### 6.1 Server operating system

**Finding:** DC01 was identified as Windows Server 2012 R2 Standard Evaluation.

**Evidence:** Operating-system information in the DC01 disk image examined through Autopsy.

**Confidence:** High.

### 6.2 Desktop operating system

**Finding:** The desktop was identified as Windows 10 Enterprise Evaluation, ReleaseID 2004.

**Evidence:** Microsoft\Windows NT\CurrentVersion values in the desktop SOFTWARE hive examined with Registry Explorer.

**Confidence:** High.

### 6.3 Server time-zone configuration

**Finding:** The server registry indicated Pacific Standard Time.

**Evidence:** TimeZoneInformation in the server SYSTEM hive.

**Confidence:** High for configuration. Event timestamps still require source-specific normalization.

### 6.4 RDP-related activity

**Finding:** The PCAP contained repeated traffic involving 194.61.24.102 and RDP/3389 that was investigated as possible password-guessing activity.

**Evidence:** Wireshark review of repeated TCP activity to the RDP service.

**Confidence:** Medium to high for repeated RDP activity. A successful brute-force login requires authentication or session evidence in addition to SYN or connection attempts.

### 6.5 Presence of coreupdater.exe

**Finding:** coreupdater.exe was identified under C:\Windows\System32.

**Evidence:** Disk-image examination using FTK Imager and Autopsy, with supporting metadata and hash enrichment.

**Confidence:** High for file presence and path.

### 6.6 Persistence

**Finding:** Registry evidence indicated that coreupdater.exe was configured to run persistently, including a service entry with an automatic-start value.

**Evidence:** HKLM\SYSTEM\CurrentControlSet\Services\coreupdater or corresponding control-set path examined with Registry Explorer. The report also described desktop Run-key evidence.

**Confidence:** High for the service configuration; Run-key attribution should be tied to the specific captured value.

### 6.7 External communication

**Finding:** Memory strings and PCAP evidence associated suspicious activity with 203.78.103.109.

**Evidence:** Desktop memory strings and packet analysis.

**Confidence:** Medium to high. The external endpoint and connection can be observed; labeling it command-and-control depends on the traffic pattern and related malware evidence.

### 6.8 Access to multiple systems

**Finding:** The combined investigation found suspicious activity affecting both the desktop and DC01.

**Evidence:** Separate host artifacts and related network evidence.

**Confidence:** Medium. A definitive lateral-movement path requires normalized authentication, session, and timeline evidence.

### 6.9 Data access or exfiltration

**Finding:** The source report discussed suspicious access to sensitive directories and possible exfiltration.

**Confidence:** Unconfirmed in the public portfolio evidence. No specific transferred file, byte count, completed transfer, or recovered stolen dataset is documented here.

## 7. Timeline considerations

The classroom report references activity around September 18, 2020, an approximate timestamp of September 18 at 02:24:06 UTC, and a coreupdater.exe timestamp of September 19 at 03:23:41 EDT.

These values should not be placed in a definitive sequence until the source, time-zone basis, daylight-saving treatment, and clock accuracy are confirmed. The server was configured for Pacific time, while the training narrative identifies Colorado. This demonstrates why timestamps require provenance and normalization.

## 8. Candidate ATT&CK mappings

| Behaviour | Technique | Evidence boundary |
|---|---|---|
| RDP password attempts | T1110.001 Password Guessing | Repeated RDP traffic; authentication outcome needs corroboration |
| Remote access using RDP | T1021.001 Remote Desktop Protocol | RDP-related traffic and scenario context |
| Windows-service persistence | T1543.003 Windows Service | Services registry entry referencing coreupdater.exe |
| Registry Run-key persistence | T1547.001 Registry Run Keys / Startup Folder | Apply only when the captured Run-key value is verified |
| PowerShell execution | T1059.001 PowerShell | Apply only to recovered command or script evidence |

ATT&CK describes observed behaviour; it is not evidence of attribution to a named actor.

## 9. Recommendations

- restrict externally reachable RDP and use an approved secure administration path;
- require strong authentication for remote administration;
- separate privileged and everyday accounts;
- monitor authentication failures and successful remote sessions;
- alert on new or modified Windows services and suspicious Run keys;
- collect process, PowerShell, registry, endpoint, DNS, and network telemetry;
- segment desktop, server, and administration networks;
- protect and test backups; and
- preserve evidence and normalize timestamps during incident response.

## 10. Limitations

- This was a public training dataset, not a live-client engagement.
- The team analyzed supplied artifacts rather than collecting them.
- The repository does not redistribute the E01, memory, autoruns, or PCAP files.
- VirusTotal results can change and are not primary proof.
- Some source-report statements combine observation and inference.
- Timestamp normalization was incomplete.
- No control was deployed or tested as part of the investigation.

## 11. References

- [DFIR Madness — Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Autopsy](https://www.autopsy.com/)
- [Registry Explorer](https://ericzimmerman.github.io/)
- [Volatility Foundation](https://volatilityfoundation.org/)
- [Wireshark](https://www.wireshark.org/)
- [VirusTotal](https://www.virustotal.com/)
