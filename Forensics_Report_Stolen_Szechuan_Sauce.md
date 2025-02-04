
# Disclaimer

This project is based on an existing forensic investigation case study, "The Stolen Szechuan Sauce," as part of an educational exercise for cybersecurity training.

The findings, methodologies, and conclusions presented in this repository are for **learning and demonstration purposes only**. Any references to real-world IP addresses, malware, or attack methods are purely **simulated and do not represent actual incidents**.

All credit for the original case study goes to the **DFIR Madness** project and the respective cybersecurity tools referenced in this report.

This repository is not intended for unauthorized use, real-world investigations, or any form of illegal activities.


# Forensics Report and Documentation











Forensics Report and Documentation

Case 001 – The Stolen Szechuan Sauce







PREPARED BY
Cassandra Dsouza

Hamzah Al-Nasser



Course Name 



Cyber Security Immersive







Jan.2025

Contents




## 1. Executive Summary



The investigation into Case 001: The Stolen Szechuan Sauce uncovered a targeted cyberattack that exploited weaknesses in the victim’s network security (DFIR Madness, n.d.). The attacker gained unauthorized access by exploiting vulnerabilities in Remote Desktop Protocol (RDP), using the IP address 194.61.24.102, and deployed malicious software, coreupdater.exe, on critical systems. This malware allowed the attacker to maintain control over the compromised systems and potentially access sensitive data (VirusTotal, n.d.; Autopsy, n.d.).

Key findings include:

The attacker accessed both the Desktop and DC systems through a brute force attack on RDP and installed malware to ensure continued access.

The malware communicated with a remote server at 203.78.103.109, which enabled the attacker to issue commands and possibly steal data.

Evidence shows the attack began on September 18, 2020, and involved ongoing activity within the network.

The victim’s network infrastructure, including its key systems, was actively targeted for exploitation.

This breach demonstrates the importance of implementing stronger access controls, monitoring network traffic for suspicious activity, and conducting regular security assessments. By addressing these vulnerabilities, organizations can better protect against similar attacks in the future.




## 2. Introduction

The forensic investigation aims to examine the network breach that results in the theft of private information, commonly referred to as The Stolen Szechuan Sauce. The objectives of the investigation are to determine the attacker’s techniques, the extent of the compromise, and the artifacts left behind. By analyzing disk images, memory dumps, and network traffic, the investigation seeks to reconstruct the chronology of events and uncover the attacker’s actions (DFIR Madness, n.d.).

In this scenario, both a desktop computer and a DC system are infected. The inquiry focuses on answering critical questions about the network architecture, the malware used, the operating systems involved, and the breached data. The findings of the report aim to provide a deeper understanding of the attack vector, mitigate potential risks, and strengthen the security posture of the compromised network.



## 3. Methodology



The forensic investigation followed a structured methodology to ensure a thorough and accurate analysis of the evidence. The process involved the use of specialized tools, examination of artifacts, and a step-by-step approach to uncover the details of the breach.

## 3.1 Tools and Artifacts Used

The investigation utilized various tools to analyze the provided artifacts. Key tools and their purposes are as follows:

Autopsy: A tool for examining disk images, and retrieving important information such as registry keys, metadata and system files (Autopsy, n.d.). 

FTK Imager: Used to examine disk images and extract specific files, such as those in the System32 directory. 

Registry Explorer: Used to identify malware persistence mechanisms (coreupdater.exe in HKLM\SYSTEM\CurrentControlSet\Services), analyze network settings (Tcpip keys), confirm local time settings (TimeZoneInformation) and validate OS details (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion). 

VirusTotal: By examining file hashes, this tool confirms whether a file is dangerous It also checks for malicious IP addresses. (VirusTotal, n.d.). 

Wireshark: Employed to analyze network traffic (PCAP files) and identify suspicious IP addresses and traffic patterns (DFIR Madness, n.d.).

Strings: Extracted strings from memory dumps to locate evidence of malware, including references to coreupdater.exe and malicious IP addresses.

Disk Images: The DC01 disk image (CDriveE01), Desktop disk image (E01), memory dumps and the network traffic capture file (case001.pca) were the main artifacts examined.



Artifacts Analyzed

DC01 Disk Image: The primary artifact used to analyze system data, registry keys, and persistence mechanisms.

Desktop Disk Image (E01): Contained filesystem data for the Windows 10 machine, including malicious files such as coreupdater.exe and related registry entries.

Desktop Memory Image: Analyzed for active processes, open network connections, and strings referencing malware and malicious IPs.

PCAP File: Captured network traffic, including communication between compromised systems and malicious IP addresses (203.78.103.109 and 194.61.24.102).

Autoruns: Evaluated to identify persistence mechanisms, such as registry entries and startup configurations for coreupdater.exe.

Registry Hive Files for Desktop: (SYSTEM and SOFTWARE) Extracted from the Desktop disk image to analyze persistence and system configurations.




## 3.2 Steps Taken

## 3.2.1 DC01 Steps:

First Analysis: To determine the operating system and system files, Autopsy was used to load the disk image (CDriveE01).



Registry Analysis: To ascertain the server's local time and network configuration, the TimeZoneInformation and Tcpip registry keys were inspected using Registry Explorer.



Malware Identification: The coreupdater.exe file was marked as malicious after the System32 directory was examined to find questionable files. We used VirusTotal to verify the file hash.



Network Traffic Analysis: The case001.pcap file was examined using Wireshark, with an emphasis on spotting questionable IP addresses and traffic trends such RDP brute force attempts.



Finally, reporting to give a thorough picture of the breach, the results were recorded and backed up by screenshots and thorough justifications.



## 3.2.2 Desktop Steps

Memory Analysis:

Utilized Volatility to extract active processes, network connections, and registry activities from the memory image.

Identified the presence of the coreupdater.exe file and extracted its details.

Disk Image Analysis:

Mounted the E01 disk image in Autopsy and examined the filesystem for suspicious files and registry hives.

Located and analyzed coreupdater.exe in the Windows System32 directory.

Extracted registry hives (SOFTWARE and SYSTEM) for further analysis using Registry Explorer.

PCAP Analysis:

Opened the PCAP file in Wireshark to trace suspicious IP addresses and analyze network activity.

Identified IP addresses 203.78.103.109 and 194.61.24.102 associated with malicious activities.

Threat Intelligence:

Submitted file hashes of coreupdater.exe to VirusTotal for verification.

Persistence Mechanism Analysis:

Examined autoruns data to identify malicious startup entries.

Used Registry Explorer to confirm persistence via the Run registry key pointing to coreupdater.exe.



This methodical approach allowed for the systematic investigation of the provided artifacts, leading to the identification of the malware, its delivery mechanism, and its persistence on the system.

## 4. Findings

The forensic analysis revealed significant evidence of malicious activity on the Desktop system and associated network. The malicious file Coreupdater.exe was identified in the System32 directory, configured for persistence through autorun registry entries. Network analysis revealed that 194.61.24.102 exploited RDP to gain access to the desktop, while 203.78.103.109 acted as the Command and Control (C2) server for the malware. Persistence mechanisms included obfuscated PowerShell scripts embedded in the registry, indicating advanced evasion techniques.

On the server system, RDP exploitation was confirmed via brute-force login attempts followed by malware deployment. Analysis of timeline data and artifacts suggested attempts to enumerate files and potential data exfiltration. These findings collectively outline the attacker’s entry vector, actions, and the malware’s capabilities, providing critical insights into the breach.



## 4.1 What’s the Operating System of the Server?

By analyzing the DC01 disk image in Autopsy, I confirmed that the server's operating system was Windows Server 2012 R2 Standard Evaluation. This determination was made by examining the system files within the CDriveE01 image (Autopsy, n.d.).






## 4.2 What’s the Operating System of the Desktop? 

The operating system of the desktop is Windows 10 Enterprise Evaluation.

The screenshot below shows the registry key path ROOT\Microsoft\Windows NT\CurrentVersion, highlighting the ProductName key, which confirms the operating system as Windows 10 Enterprise Evaluation.



To identify the operating system, the SOFTWARE hive of the desktop disk image was loaded into Eric Zimmerman's Registry Explorer. The ProductName key under the path ROOT\Microsoft\Windows NT\CurrentVersion displayed the value Windows 10 Enterprise Evaluation, which confirms the OS.

Additional keys such as InstallationType (Client), and ReleaseID (2004) were reviewed to corroborate the details. These keys collectively verify that the desktop is running Windows 10 Enterprise Evaluation.




## 4.3 What was the local time of the Server?



FTK Imager was used to analyze the DC01 disk image, and pertinent files were extracted by looking through the system32\config folder. (windows 🡪system32🡪config)



Then the system32 file was then examined using Registry Explorer, and the TimeZoneInformation key showed that the server was configured for Pacific Standard Time. To record the results, screenshots were captured. By analyzing the TimeZoneInformation registry key, which verified the server's time zone as Pacific Standard Time, the local time of the server was ascertained.

## 4.4 Was there a breach?

Yes

The system was breached through two primary vectors: exploitation of RDP and malware delivery.

Desktop Memory Analysis:

Found evidence of coreupdater.exe running on the system, indicating malicious activity. The file was linked to persistence mechanisms found in the registry.

This image illustrates the analysis of the memory dump (DESKTOP-SDN1RPT.mem) using the strings tool to extract printable data, filtered with grep to identify specific artifacts like coreupdater.exe. The filtered results, saved in relevant_strings.txt, confirmed the presence of coreupdater.exe, linking it to malicious activity and supporting evidence of malware persistence in the system.

## 4.5 What was the initial entry vector?

To obtain access, the attacker utilized the IP address 194.61.24.102.
This may be stated because by examining questionable network activity and tracking down the source IP address, the first entry vector was found.






In addition to that RDP Brute Force attacks were identified due to a high number of SYN requests aimed at the same destination port. This unusual traffic pattern was detected using the filter "ip.addr == 194.61.24.102 and tcp" in the case001.pcap capture file, indicating potential unauthorized access attempts through RDP.






## 4.6 Was malware used? If so, what was it?

Yes, the malware used was coreupdater.exe. The malicious process was coreupdater.exe, located at C:\Windows\System32\coreupdater.exe. 



The file hash was analyzed using VirusTotal, confirming it as malicious, and screenshots were taken as evidence. The malicious nature of the process was identified by analyzing the file hash and verifying it through VirusTotal.

“eed41b4500e473f97c50c7385ef5e374","fd153c66386ca93ec9993d66a84d6f0d129a3a5c","20200918_0347_CDrive.E01\Partition 2 [11168MB]\NONAME [NTFS]\[root]\Windows\System32\coreupdater.exe”


The malware, coreupdater.exe was also found in the C:\Windows\System32\ directory, with registry entries in both Run and Services keys for persistence. The screenshot below shows coreupdater found in the registry explorer

## 4.6.1 What process was malicious?

The coreupdater.exe process was malicious

Process:

Metadata analysis in Autopsy and Registry Explorer confirmed the process as unauthorized and unsigned.

The file path (C:\Windows\System32\coreupdater.exe) and registry entries confirmed it was part of the breach.

The screenshot below shows the metadata which is lacking a signature indicating it is unsigned.



## 4.6.2 Identify the IP Address that delivered the payload.

The payload was delivered from 194.61.24.102. The IP address was found in the web history, indicating suspicious activity, and a screenshot was taken as evidence. The IP address was identified by examining the web history and noting the use of an insecure HTTP protocol.





## 4.6.3 What IP Address is the malware calling to?

Based on the evidence so far, the IP address that the malware is calling to is 203.78.103.109. This conclusion is supported by the following findings:

Evidence Supporting the Finding:

Memory Analysis:

The analysis of memory dumps or strings showed a connection being established with 203.78.103.109.

This matches the behavior of typical Command-and-Control (C2) infrastructure used by malware.

PCAP Analysis:

Reviewing the captured network traffic (PCAP file) indicated active connections from the compromised system to 203.78.103.109 on specific ports, suggesting C2 activity.

This IP address appeared in logs with communication patterns matching those of malware callbacks.

Registry and Persistence Mechanism:

The malware (coreupdater.exe) installed as a service was likely configured to communicate with 203.78.103.109 as part of its persistence and remote control strategy.

## 4.6.4 Where is this malware on disk?

C:\Windows\System32\coreupdater.exe.






## 4.6.5 When did it first appear?

The malware first appeared on 2020-09-19 03:23:41 EDT.



## 4.6.6 Did someone move it?

Based on the current findings:

There is no conclusive evidence yet that coreupdater.exe was moved. It appears to have been created or downloaded directly into C:\Windows\System32.

## 4.6.7 What were the capabilities of this malware?

coreupdater.exe was identified as malicious software with a range of capabilities designed to maintain persistence, communicate with a Command-and-Control (C2) server, and execute malicious operations on the victim system. Below is a summary of its observed and inferred functionalities:

Key Capabilities:

Persistence:

Configured to automatically start on boot via the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\coreupdater registry key.

Ensures the malware remains active after system reboots.

Command-and-Control (C2) Communication:

Outbound communication to a known malicious C2 IP: 203.78.103.109.

Likely used to receive commands and potentially exfiltrate data.

Fileless Execution:

Executes obfuscated PowerShell scripts directly from memory, avoiding detection by traditional antivirus solutions.

Leveraged to download and execute additional payloads or commands.

Privilege Escalation:

Placement in C:\Windows\System32 indicates the attacker had administrative-level access, granting extensive system control.

Data Exfiltration:

Capability to send sensitive data to the attacker’s C2 infrastructure.

Obfuscation:

Malware file is XOR-encoded to evade detection by signature-based tools.

Alters system timestamps to hinder forensic investigation.

Network Activity:

Suspected involvement in RDP exploitation, potentially as part of lateral movement within the network.

Links to another IP, 194.61.24.102, seen exploiting port 3389 (RDP).

Anti-Forensic Behavior:

Modifies system artifacts to obscure its presence and make forensic recovery difficult.

Evidence and Analysis:

Registry Key: Configured in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services.

Network Analysis: PCAP files revealed communication to 203.78.103.109 and suspicious RDP activity involving 194.61.24.102.

Memory and File Analysis: Detected obfuscated PowerShell commands, indicating advanced evasion tactics.

This screenshot shows the persistence mechanism for coreupdater.exe in the Windows Registry under HKLM\SYSTEM\ControlSet001\Services\coreupdater. The Start value is set to 2, which indicates that the service is configured to start automatically during system boot.




## 4.6.8 Is this malware easily obtained?

The coreupdater.exe malware is likely a custom payload generated using widely available tools like Metasploit or Cobalt Strike, known for enabling easy payload creation. It demonstrates low complexity, with minimal obfuscation and the use of standard PowerShell commands. Such tools and techniques are common in public repositories and underground forums. However, the malware's deployment, including targeted persistence mechanisms and specific Command-and-Control IPs, suggests deliberate tailoring for the victim environment. While it isn't highly sophisticated, its creation likely required basic technical knowledge and access to offensive security tools.

## 4.6.9 Was this malware installed with persistence on any machine?

Yes, the malware was installed with persistence, as evidenced by its presence in the System32 directory.

Additionally, it was configured to run on system boot in the Windows Registry.



## 4.7 What malicious IP Addresses were involved?



The malicious IP addresses involved were 194.61.24.102 and 203.78.103.109. The IP addresses were identified as malicious through analysis in VirusTotal.







4.7.1 Were any IP Addresses from known adversary infrastructure?
Yes, the identified IP addresses were flagged as malicious on VirusTotal. This indicates they are likely associated with known adversary infrastructure used in cyberattacks. The IPs’ presence in VirusTotal's database confirms their involvement in suspicious or harmful activity, linking them to malicious campaigns or operations.

## 4.7.2 Are These Pieces of Adversary Infrastructure Involved in Other Attacks Around the Time of the Attack?

Yes, based on VirusTotal and other threat intelligence tools, the identified IP addresses were involved in other malicious activities around the same timeframe. These include hosting malware payloads, participating in phishing campaigns, and serving as Command-and-Control (C2) servers. The repeated association of these IPs with malicious behavior further validates their use as adversary infrastructure in coordinated attacks.






## 4.8 Did the attacker access any other systems?

Yes, the attacker accessed both the Desktop and DC systems. Evidence of access to both systems was found during the investigation.

How?

Exploiting RDP Vulnerabilities: Logs show brute force attempts from IP 194.61.24.102 targeting RDP services.

Command-and-Control (C2) Communication: IP 203.78.103.109 acted as the C2 server, enabling the attacker to deploy commands and move laterally within the network.

When?

Initial compromise: September 18, 2020, at approximately 02:24:06 UTC, based on RDP logs and PCAP evidence of the coreupdater.exe payload download.

Lateral movement followed shortly after.

Did the Attacker Steal or Access Any Data?

Evidence: Coreupdater.exe suggests potential exfiltration activities. File access logs and timeline analysis reveal suspicious activity in sensitive directories.

Timestamps: Data access began around September 18, 2020, 02:24:06 UTC, coinciding with the malware deployment and continued during the session via RDP.






## 4.9 What was the network layout of the victim network?



The victim network had an IP address of 10.42.85.10. The network layout was determined by analyzing the Tcpip registry key using Autopsy, and a screenshot was taken as evidence. The network layout was identified by examining the Tcpip registry key, which revealed the IP address of the victim network. 

(Windows🡪system32🡪config🡪system🡪controlset001🡪services 🡪Tcpip).








## 5. Conclusion

The investigation into Case 001: The Stolen Szechuan Sauce revealed a sophisticated attack involving multiple entry points and coordinated malicious activity. The attacker exploited an RDP vulnerability via the IP address 194.61.24.102, gaining unauthorized access to the victim’s network. Following the breach, they deployed malware (coreupdater.exe) into the critical C:\Windows\System32 directory. This file was identified as part of their persistence mechanism, linked to registry startup keys and services, ensuring continuous control over the machine. (DFIR Madness, n.d.; Autopsy, n.d.; VirusTotal, n.d.).

Further analysis of the Desktop system revealed evidence of both memory-based and filesystem-level compromises. coreupdater.exe was first identified during memory analysis, while subsequent investigations into the E01 disk image confirmed its persistence via registry entries. Network traffic analysis highlighted communication with the Command-and-Control (C2) server at 203.78.103.109, enabling remote command execution and possible data exfiltration (VirusTotal, n.d.).

The attacker accessed both the Desktop and DC systems, demonstrating lateral movement within the network. The malware first surfaced on 2020-09-19, aligning with suspicious events observed in the PCAP file and RDP logs. The victim network, identified as 10.42.85.0/24, was targeted for prolonged exploitation, with the Desktop acting as a critical foothold in the attacker’s campaign.

This case underscores the need for robust defenses, including stricter access controls, regular vulnerability assessments, and real-time monitoring, to prevent similar breaches in the future.




## 6. References





[1] Autopsy. (n.d.). Autopsy documentation. Retrieved January 26, 2025, from https://www.autopsy.com/



[2] Basis Technology. (2025). Autopsy user documentation. Retrieved January 26, 2025, from https://www.autopsy.com/support/documentation/



[3] DFIR Madness. (n.d.). Case 001 – The stolen Szechuan sauce. Retrieved January 26, 2025, from https://dfirmadness.com/the-stolen-szechuan-sauce/



[4] Eric Zimmerman’s Registry Explorer. (n.d.). Registry Explorer. Retrieved January 26, 2025, from https://ericzimmerman.github.io/



[5] MITRE. (n.d.). MITRE ATT&CK framework. Retrieved January 26, 2025, from https://attack.mitre.org/



[6] VirusTotal. (n.d.). VirusTotal website. Retrieved January 26, 2025, from https://www.virustotal.com/



[7] Wireshark. (n.d.). Wireshark: Go deep. Retrieved January 26, 2025, from https://www.wireshark.org/

