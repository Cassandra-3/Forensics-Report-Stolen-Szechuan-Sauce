# Forensic Investigation: The Stolen Szechuan Sauce

A team-based digital forensics case study using the public [DFIR Madness Case 001 training dataset](https://dfirmadness.com/the-stolen-szechuan-sauce/).

**Program:** Lighthouse Labs — Cyber Security Immersive  
**Completed:** January 2025  
**Project type:** Team academic investigation  
**Investigators:** Cassandra Dsouza and Hamzah Al-Nasser  
**Environment:** Public training artifacts; not a live client incident

## Case objective

The investigation examined disk, memory, registry, autoruns, and packet-capture artifacts to reconstruct activity affecting a Windows desktop and a domain controller.

The team investigated:

- operating-system and network configuration;
- suspected RDP password-guessing activity;
- the presence and persistence of coreupdater.exe;
- communication with external infrastructure;
- relationships between desktop and server artifacts; and
- the confidence and limitations of each conclusion.

## Confirmed contribution split

The original Word report uses colour to distinguish the two workstreams.

### Cassandra Dsouza — DC01/server workstream

Cassandra completed the uncoloured/DC01-focused sections, including:

- DC01 disk-image examination;
- identification of Windows Server 2012 R2 Standard Evaluation;
- extraction and examination of server registry material;
- server time-zone and network-configuration analysis;
- investigation of RDP traffic and the suspected initial-access source;
- identification and examination of coreupdater.exe in server artifacts;
- documentation of supporting screenshots and findings; and
- methodology, report integration, and concluding analysis.

### Hamzah Al-Nasser — desktop workstream

Hamzah completed the purple desktop-focused sections, including:

- desktop memory examination;
- desktop E01 and registry-hive analysis;
- PCAP review from the desktop workstream;
- process, persistence, and C2 analysis for coreupdater.exe;
- VirusTotal enrichment;
- desktop operating-system verification; and
- assessment of malware capabilities and related activity.

The executive summary and final report combine evidence from both workstreams and are presented as team conclusions.

## Evidence sources and tools

| Evidence source | Purpose | Tools used |
|---|---|---|
| DC01 E01 disk image | Server OS, registry, filesystem, network configuration, suspicious files | Autopsy, FTK Imager, Registry Explorer |
| Desktop E01 disk image | Desktop filesystem, registry hives, malware path and metadata | Autopsy, FTK Imager, Registry Explorer |
| Desktop memory image | Processes, strings, possible connections and in-memory activity | Volatility, Strings |
| Case001 PCAP | RDP traffic and external communications | Wireshark |
| Autoruns and registry artifacts | Startup and service persistence | Autoruns data, Registry Explorer |
| Hash and IP enrichment | External reputation context | VirusTotal |

## Principal findings

- The server artifact was identified as Windows Server 2012 R2 Standard Evaluation.
- The desktop artifact was identified as Windows 10 Enterprise Evaluation.
- Repeated traffic involving RDP/3389 and 194.61.24.102 supported investigation of password-guessing activity.
- coreupdater.exe was located under C:\Windows\System32.
- Registry evidence indicated that the executable was configured for persistence, including a Windows service entry.
- Memory and PCAP evidence associated suspicious activity with 203.78.103.109.
- The available evidence supported possible access to both the desktop and DC01.
- The report discussed possible data access or exfiltration, but the available portfolio evidence does not establish confirmed data theft.

See the [evidence matrix](docs/evidence-matrix.md) for source, confidence, and limitation details.

## Candidate MITRE ATT&CK mappings

These mappings describe behaviours supported by the evidence; they do not identify a specific threat actor.

| Observed behaviour | Candidate mapping |
|---|---|
| Repeated RDP authentication activity | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| Use of RDP for remote access | [T1021.001 — Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/) |
| Service-based persistence | [T1543.003 — Windows Service](https://attack.mitre.org/techniques/T1543/003/) |
| Registry Run-key persistence, where corroborated | [T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |
| Obfuscated PowerShell evidence, where corroborated | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) |

## Repository contents

- [Structured forensic report](Forensics_Report_Stolen_Szechuan_Sauce.md)
- [Evidence and confidence matrix](docs/evidence-matrix.md)

## Skills demonstrated

- Disk-image and filesystem analysis
- Windows registry analysis
- Network packet analysis
- Malware persistence investigation
- Timeline and cross-artifact correlation
- Evidence documentation and forensic reporting
- Team investigation and workstream integration
- Technical finding qualification and limitation analysis

## Scope and limitations

This project used artifacts published for a forensic training exercise. The team did not collect evidence from a live client, interact with a victim environment, or perform containment. The repository does not redistribute the original forensic images.

Historical IP-address or file-hash reputation is supporting context, not proof by itself. Some timestamps in the classroom report use different time zones and must be normalized before asserting a definitive attack timeline.
