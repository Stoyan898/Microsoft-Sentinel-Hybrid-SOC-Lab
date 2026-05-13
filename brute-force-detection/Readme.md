Overview

This lab demonstrates brute-force detection using Microsoft Sentinel and Windows Security Event logs.

A local Windows 11 VM connected through Azure Arc was used to generate failed login attempts (Event ID 4625). Logs were ingested into Microsoft Sentinel using Azure Monitor Agent (AMA) and analyzed using KQL.

Objectives
Detect multiple failed login attempts
Build custom KQL detection logic
Create Scheduled Analytics Rule
Generate Sentinel incidents automatically
Map detection to MITRE ATT&CK
Technologies Used
Microsoft Sentinel
Azure Arc
Azure Monitor Agent (AMA)
Windows 11 VM
VirtualBox
KQL

SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5

MITRE ATT&CK Mapping
Tactic	Technique
Credential Access	T1110 - Brute Force
Detection Results

The Scheduled Analytics Rule successfully generated Sentinel incidents after multiple failed login attempts were created on the monitored endpoint.
