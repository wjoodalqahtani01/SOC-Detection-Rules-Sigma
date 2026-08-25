# 🛡️ SOC Threat Detection Rules (Sigma & MITRE ATT&CK Alignment)

## 📌 Project Overview
This repository contains custom-built **Sigma Rules** designed to enhance SIEM detection capabilities within a Security Operations Center (SOC). Sigma is a standardized, vendor-agnostic format used to write detection signatures for log analysis platforms (Splunk, Elastic, QRadar, etc.).

---

## 🎯 Detection Case Study: Suspicious PowerShell Encoded Command Execution

### Rule Description
Detects instances where PowerShell executes base64 encoded commands (`-EncodedCommand` / `-e`), a common technique used by threat actors to obfuscate malicious scripts and evade initial detection.

### 📝 Sigma Rule Syntax (YAML)
```yaml
title: Suspicious Encoded PowerShell Execution
id: f4b12c8a-9812-4a5f-b203-1289190ab123
status: experimental
description: Detects PowerShell command line execution using encoded payloads.
author: Wjood Alqahtani
date: 2026-08-25
references:
    - [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - ' -e '
            - ' -enc '
            - ' -EncodedCommand '
    condition: selection
falsepositives:
    - Administrative maintenance scripts utilizing standard encoding.
level: high
tags:
    - attack.execution
    - attack.t1059.001

🔎 Equivalent Splunk Search Query (SPL)
index=win_logs EventCode=4688 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") (CommandLine="* -e *" OR CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *")

🧐 SOC Analyst Commentary & Threat Assessment
1. Technical Context & Threat Behavior
Threat Mechanism: Attackers leverage powershell.exe -EncodedCommand to obscure command arguments from traditional process monitoring and command-line logging.

Verdict: High-confidence rule for identifying early-stage script execution and fileless malware delivery.

2. MITRE ATT&CK Mapping
Tactic: Execution (TA0002)

Technique: Command and Scripting Interpreter: PowerShell (T1059.001)

Technique: Obfuscated Files or Information (T1027)

3. Tuning & SIEM Deployment Recommendations
False Positive Reduction: Exclude approved IT automation service accounts running pre-verified PowerShell tasks.

Response Action: Automatically trigger endpoint isolation if executed by non-administrative users.
