
# 🧩 Sysmon Ingestion Lab – Microsoft Sentinel

🚀 Hands-on lab focused on ingesting Sysmon telemetry into Microsoft Sentinel for advanced endpoint visibility and threat hunting.

---

## 🎯 What This Lab Demonstrates

- Sysmon installation and configuration
- Azure Arc hybrid endpoint onboarding
- Azure Monitor Agent (AMA) deployment
- Sysmon Operational log ingestion
- Process creation monitoring
- Endpoint telemetry collection
- KQL-based log analysis
- Threat hunting preparation

---

## 🧰 Technologies Used

- Microsoft Sentinel
- Azure Arc
- Azure Monitor Agent (AMA)
- Sysmon
- SwiftOnSecurity Sysmon Configuration
- Windows 11 VM
- VirtualBox
- KQL (Kusto Query Language)

---

## 🏗️ Lab Architecture

Windows 11 VM (VirtualBox)
        ↓
Sysmon
        ↓
Azure Monitor Agent (AMA)
        ↓
Azure Arc
        ↓
Log Analytics Workspace
        ↓
Microsoft Sentinel

---

## ⚙️ Sysmon Configuration

Sysmon was configured using the popular:

```text
SwiftOnSecurity Sysmon Configuration

🔧 Sysmon Installation
Verify Sysmon Service
Get-Service Sysmon64
Apply Sysmon Configuration
.\Sysmon64.exe -accepteula -c sysmonconfig-export.xml
📡 Data Collection Rule (DCR)

A dedicated Data Collection Rule was created for Sysmon telemetry ingestion.

Event Channel Collected
Microsoft-Windows-Sysmon/Operational!*
Destination
Log Analytics Workspace
Microsoft Sentinel
🧪 Event Generation

The following commands were executed to generate Sysmon process creation events:

whoami
ipconfig
hostname
Get-Process
🔍 Verification Queries
Basic Sysmon Query
Event
| where Source == "Microsoft-Windows-Sysmon"
| take 10
Process Creation Monitoring
Event
| where EventID == 1
| where Source == "Microsoft-Windows-Sysmon"
| sort by TimeGenerated desc
🧠 Detection Capabilities Enabled

This lab enabled:

Process creation monitoring
Command-line visibility
PowerShell activity monitoring
Endpoint telemetry collection
Threat hunting workflows
Detection engineering preparation
