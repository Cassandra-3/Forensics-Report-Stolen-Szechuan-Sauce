# Forensics-Report-Stolen-Szechuan-Sauce

## 📌 Project Overview
This repository contains a forensic investigation case study titled **"The Stolen Szechuan Sauce."** The case was analyzed as part of a cybersecurity training program to practice **Digital Forensics and Incident Response (DFIR)** techniques.

The investigation focuses on identifying **malware**, **compromised systems**, and **attack vectors** using real forensic methodologies.

## 🔍 Case Summary
A **network breach** was detected, leading to unauthorized access and malware installation on critical systems. The attack involved **Remote Desktop Protocol (RDP) exploitation** and deployment of a malicious executable (`coreupdater.exe`). The goal was to determine:
- The attacker's **initial entry vector**.
- The **malware's** behavior and persistence mechanisms.
- The **malicious IP addresses** involved.
- The impact on **compromised systems**.

## 🛠️ Methodology
The forensic investigation followed a structured process:
1. **Evidence Collection** – Acquiring disk images, memory dumps, and network traffic logs.
2. **Analysis** – Using forensic tools to identify malware, registry modifications, and network activity.
3. **Correlation** – Mapping findings to known attack patterns (MITRE ATT&CK framework).
4. **Reporting** – Summarizing findings with detailed evidence and recommendations.

## 📊 Findings
- **Malware Identified**: `coreupdater.exe` (used for persistence and C2 communication).
- **Exploitation Method**: **Brute-force attack** on RDP.
- **Malicious IPs Involved**: `194.61.24.102` (initial access) and `203.78.103.109` (Command-and-Control server).
- **Compromised Systems**: Both **Desktop** and **Domain Controller (DC01)** were accessed.
- **Persistence Mechanism**: Malware executed via **Windows Registry startup entries**.
- **Potential Data Exfiltration** detected.

## 🛠️ Tools Used
The following tools were utilized to conduct the forensic investigation:
- **Autopsy** – Disk image analysis.
- **FTK Imager** – Extracting forensic artifacts.
- **Wireshark** – Network traffic analysis.
- **Registry Explorer** – Examining Windows registry for persistence mechanisms.
- **VirusTotal** – Checking file hashes and malicious IP addresses.
- **Volatility** – Memory forensics.
- **MITRE ATT&CK Framework** – Identifying attack tactics and techniques.

## ⚠️ Disclaimer
This project is based on an existing forensic investigation case study for **educational purposes only**.  
- Any references to **IP addresses, malware, or attack techniques** are **simulated** and not related to real-world incidents.
- The findings and methodologies presented are intended for **cybersecurity learning and training purposes**.
- Unauthorized use of this information for malicious purposes is strictly prohibited.

## 🚀 How to Use This Repository
1. Review the **[Forensic Report](Forensics_Report_Stolen_Szechuan_Sauce.md)** for full details.
2. Explore the provided artifacts (if applicable).
3. Use this repository as a **reference** for learning digital forensics techniques.

## 📚 References
- [Autopsy Documentation](https://www.autopsy.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [VirusTotal](https://www.virustotal.com/)
- [Wireshark](https://www.wireshark.org/)

---
📢 *Forensic investigation by Cassandra Dsouza & Hamzah Al-Nasser, as part of Cyber Security Immersive Training (Jan 2025).*
