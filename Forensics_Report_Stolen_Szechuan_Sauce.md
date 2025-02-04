## 📜 Disclaimer

This project is based on an existing forensic investigation case study, **"The Stolen Szechuan Sauce,"** as part of an educational exercise for cybersecurity training.

The findings, methodologies, and conclusions presented in this repository are for **learning and demonstration purposes only**. Any references to **real-world IP addresses, malware, or attack methods** are purely **simulated and do not represent actual incidents**.

All credit for the original case study goes to the **DFIR Madness** project and the respective cybersecurity tools referenced in this report.

🚨 This repository is **not intended** for unauthorized use, real-world investigations, or any form of illegal activities.


---

## 🕵️ Executive Summary

The investigation into **Case 001: The Stolen Szechuan Sauce** uncovered a **targeted cyberattack** that exploited weaknesses in the victim’s network security. The attacker gained **unauthorized access** by exploiting **Remote Desktop Protocol (RDP)** vulnerabilities, using the IP address **194.61.24.102**, and deployed **malicious software (coreupdater.exe)** on critical systems.

### 🔑 Key Findings:

✅ **The attacker accessed both the Desktop and DC systems** via an **RDP brute-force attack**.  
✅ **The malware (coreupdater.exe) established persistence** and allowed remote control.  
✅ **Command-and-Control (C2) Server identified** at **203.78.103.109**.  
✅ **Attack began on September 18, 2020**, with evidence of ongoing malicious activity.  
✅ **Victim’s network was actively targeted**, highlighting the need for stronger **access controls and security monitoring**.  

---

## 🛠️ Methodology

The forensic investigation followed a structured **Digital Forensics and Incident Response (DFIR)** methodology using specialized tools:

### 🔬 Tools & Techniques Used:

- **📂 Autopsy** – Disk image analysis
- **📀 FTK Imager** – Extracting forensic artifacts
- **📊 Wireshark** – Network traffic analysis (PCAP file inspection)
- **🛑 Registry Explorer** – Examining Windows registry for malware persistence
- **🦠 VirusTotal** – Checking file hashes and malicious IP addresses
- **🖥️ Volatility** – Memory forensics
- **🛡️ MITRE ATT&CK Framework** – Mapping attacker behavior

The investigation focused on **disk images, memory dumps, and network traffic** to reconstruct the attack timeline.

---

## 🔍 Findings & Analysis

### 🖥️ **Operating Systems Identified**

- **Server (DC01)**: **Windows Server 2012 R2 Standard Evaluation**  
- **Desktop**: **Windows 10 Enterprise Evaluation**  

### 🚨 **Breach Details**

- **Attack Method:** Exploited **Remote Desktop Protocol (RDP)** via brute-force attempts.  
- **Initial Compromise:** **IP Address 194.61.24.102** was the first attacker entry point.  
- **Malware Used:** **coreupdater.exe**, detected in `C:\Windows\System32\`.  
- **C2 Communication:** Malware connected to **203.78.103.109** for remote control.  
- **Persistence Mechanism:** Registry key modifications ensured malware execution on startup.  

---

## 📡 Malicious IP Addresses Involved

### 🌍 **Attacker Infrastructure:**

| 🚀 IP Address       | 🎯 Role |
|--------------------|------------------|
| **194.61.24.102** | Initial access - RDP brute force attack |
| **203.78.103.109** | Command-and-Control (C2) Server |

These IPs were flagged as **malicious on VirusTotal**, indicating involvement in other attacks.

---

## ⚠️ Conclusion

The forensic analysis provided **clear evidence of unauthorized access, malware deployment, and command-and-control activity**.

🔹 **Key Takeaways:**  
✅ Strengthen **access controls** (e.g., enforce MFA for RDP).  
✅ Implement **SIEM monitoring** to detect **brute-force attempts** early.  
✅ Regularly **scan for persistence mechanisms** in the **Windows registry**.  

**🚀 By addressing these security gaps, organizations can prevent future breaches!**

---

## 📚 References

- 🔍 **[Autopsy Documentation](https://www.autopsy.com/)**  
- 🛑 **[MITRE ATT&CK Framework](https://attack.mitre.org/)**  
- 🦠 **[VirusTotal](https://www.virustotal.com/)**  
- 📊 **[Wireshark - Network Analysis](https://www.wireshark.org/)**  

---

📢 **Forensic investigation by Cassandra Dsouza & Hamzah Al-Nasser**  
📅 **Cyber Security Immersive Training - January 2025**
