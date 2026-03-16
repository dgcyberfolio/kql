# 🛡️ KQL Detections

> A curated library of KQL (Kusto Query Language) detection queries mapped to the [MITRE ATT&CK Framework](https://attack.mitre.org/), designed for Microsoft Sentinel threat hunting and incident response.

---

## 📋 Table of Contents

- [Reconnaissance & Scoping](#-reconnaissance--scoping)
- [Initial Access](#-initial-access)
- [Execution](#-execution)
- [Persistence](#-persistence)
- [Credential Access](#-credential-access)
- [Discovery](#-discovery)
- [Lateral Movement](#-lateral-movement)
- [Collection & Exfiltration](#-collection--exfiltration)
- [Impact](#-impact)
- [Quick Reference — Windows Event IDs](#-quick-reference--windows-event-ids)

---

## 🔍 Reconnaissance & Scoping

### Event Overview

| Field | Value |
|---|---|
| **Category** | Scoping |
| **MITRE Tactic** | Reconnaissance |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-01-14 19:00) .. datetime(2026-01-14 22:00))
| summarize Count = count() by EventID
| order by Count desc
```

> **Remember:** Run first to understand available telemetry. High `4625` = brute force. `4688` = process execution goldmine.

---

### Host Identification

| Field | Value |
|---|---|
| **Category** | Scoping |
| **MITRE Tactic** | Reconnaissance |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-01-14 19:00) .. datetime(2026-01-14 22:00))
| summarize Count = count() by Computer
| order by Count desc
```

> **Remember:** Highest event count often = patient zero. Compare DC vs workstation activity levels.

---

## 🚪 Initial Access

### External RDP Logins

| Field | Value |
|---|---|
| **MITRE Technique** | [T1078.002 — Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **MITRE Tactic** | Initial Access |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (10, 3)
| where TargetUserName !endswith "$"
| where IpAddress == "84.252.95.165"
| project TimeGenerated, TargetUserName, LogonType, IpAddress, Computer
```

> **Remember:** `LogonType 10` = RDP, `3` = Network. Filter machine accounts (`$`). Same external IP across multiple accounts = highly suspicious.

---

### Compromised Account Timeline

| Field | Value |
|---|---|
| **MITRE Technique** | [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **MITRE Tactic** | Initial Access, Persistence, Privilege Escalation, Defense Evasion |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (10, 3)
| where TargetUserName in ("j.wilson", "helpdesk", "svc_backup")
| project TimeGenerated, TargetUserName, LogonType, IpAddress, Computer
| order by TimeGenerated asc
```

> **Remember:** Replace account names with your suspects. Look for account switching patterns across hosts.

---

## ⚙️ Execution

### Parent Process Hunt

| Field | Value |
|---|---|
| **MITRE Technique** | [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/) |
| **MITRE Tactic** | Execution |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4688
| where ParentProcessName has_any ("explorer.exe", "outlook.exe", "chrome.exe", "winword.exe", "excel.exe")
| project TimeGenerated, TargetUserName, NewProcessName, CommandLine, ParentProcessName
```

> **Remember:** `explorer.exe` spawning unusual processes = user double-clicked something. Office app → `cmd`/`powershell` = macro execution.

---

### Malware Child Processes

| Field | Value |
|---|---|
| **MITRE Technique** | [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| **MITRE Tactic** | Execution |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4688
| where ParentProcessName has "NHS_Spine_Certificate_Tool.exe"
| project TimeGenerated, TargetUserName, NewProcessName, CommandLine, ParentProcessName
```

> **Remember:** Replace malware name with your identified payload. Look for child processes: `msiexec`, `powershell`, `cmd`, `reg`, `schtasks`.

---

### LOLBin Execution

| Field | Value |
|---|---|
| **MITRE Technique** | [T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) |
| **MITRE Tactic** | Defense Evasion |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has_any ("certutil", "mshta", "regsvr32", "rundll32", "wscript", "bitsadmin", "msiexec")
| project TimeGenerated, TargetUserName, NewProcessName, CommandLine, ParentProcessName
```

> **Remember:** `msiexec` + URL = remote payload fetch. `certutil -urlcache` = download cradle. `rundll32` + `comsvcs.dll` = LSASS dump attempt.

---

## 🔒 Persistence

### Service Installation

| Field | Value |
|---|---|
| **MITRE Technique** | [T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/) |
| **MITRE Tactic** | Persistence, Privilege Escalation |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4697
| extend ServiceName = extract("<Data Name='ServiceName'>(.*?)</Data>", 1, EventData)
| extend ServiceFileName = extract("<Data Name='ServiceFileName'>(.*?)</Data>", 1, EventData)
| project TimeGenerated, Computer, ServiceName, ServiceFileName, Account
| order by TimeGenerated asc
```

> **Remember:** `4697` = Security log service install. `ServiceName`/`ServiceFileName` extracted from EventData XML. Services in `Temp`/`AppData` = suspicious. Same service across multiple hosts = lateral spread.

---

### Account Creation

| Field | Value |
|---|---|
| **MITRE Technique** | [T1136.002 — Create Account: Domain Account](https://attack.mitre.org/techniques/T1136/002/) |
| **MITRE Tactic** | Persistence |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID in (4720, 4728, 4732)
| project TimeGenerated, Computer, EventID, TargetUserName, SubjectUserName, MemberName
| order by TimeGenerated asc
```

> **Remember:** `4720` = Account created. `4728` = Added to Domain Admins. `4732` = Added to Local Admins. `SubjectUserName` = who made the change.

---

## 🔑 Credential Access

### Kerberoasting Detection

| Field | Value |
|---|---|
| **MITRE Technique** | [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) |
| **MITRE Tactic** | Credential Access |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4769
| project TimeGenerated, Computer, EventData
| order by TimeGenerated asc
```

> **Remember:** Look for `TicketEncryptionType: 0x17` (RC4) in `EventData`. `ServiceName` = user account (not `machine$`). RC4 tickets are offline-crackable.

---

### LSASS Dump Detection

| Field | Value |
|---|---|
| **MITRE Technique** | [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| **MITRE Tactic** | Credential Access |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has_any ("procdump", "rundll32", "taskmgr", "comsvcs")
   or CommandLine has_any ("minidump", "lsass", ".dmp", "sekurlsa")
| project TimeGenerated, TargetUserName, NewProcessName, CommandLine
```

> **Remember:** `rundll32` + `comsvcs.dll` + `MiniDump` = LSASS dump. `procdump -ma lsass.exe` = Sysinternals method.

---

## 🔎 Discovery

### Network Share Access

| Field | Value |
|---|---|
| **MITRE Technique** | [T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/) |
| **MITRE Tactic** | Discovery |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 5145
| where SubjectUserName in ("j.wilson", "helpdesk", "svc_backup", "adminbak")
| summarize Count = count() by SubjectUserName, ShareName, RelativeTargetName
| order by Count desc
```

> **Remember:** `IPC$` + `samr` = user enumeration. `IPC$` + `lsarpc` = policy enumeration. `SYSVOL` access = GPO reconnaissance.

---

### Share Write Access

| Field | Value |
|---|---|
| **MITRE Technique** | [T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) |
| **MITRE Tactic** | Lateral Movement |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 5145
| where AccessMask has_any ("0x2", "0x4", "0x100")
| where SubjectUserName in ("helpdesk", "svc_backup", "adminbak")
| project TimeGenerated, Computer, SubjectUserName, ShareName, RelativeTargetName
```

> **Remember:** `AccessMask 0x2` = Write, `0x4` = Append. Indicates file staging or payload deployment to shares.

---

## 🔀 Lateral Movement

### Cross-Host Process Execution

| Field | Value |
|---|---|
| **MITRE Technique** | [T1021.006 — Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/) |
| **MITRE Tactic** | Lateral Movement |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4688
| where ParentProcessName has_any ("Velociraptor", "WmiPrvSE", "wsmprovhost")
| project TimeGenerated, Computer, TargetUserName, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated asc
```

> **Remember:** Same parent process across multiple hosts = lateral spread indicator. `WmiPrvSE` = WMI lateral movement. `wsmprovhost` = WinRM execution.

---

## 📦 Collection & Exfiltration

### Archive Creation

| Field | Value |
|---|---|
| **MITRE Technique** | [T1560.001 — Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/) |
| **MITRE Tactic** | Collection |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("zip", "rar", "7z", "tar", "Compress-Archive", "makecab")
| project TimeGenerated, Computer, TargetUserName, NewProcessName, CommandLine
```

> **Remember:** `Compress-Archive` = PowerShell native compression. Look for destination in `Temp` folders. Large archives = bulk data collection.

---

### Data Transfer Tools

| Field | Value |
|---|---|
| **MITRE Technique** | [T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/) |
| **MITRE Tactic** | Exfiltration |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("curl", "wget", "Invoke-WebRequest", "certutil -urlcache", "rclone", "cloudflared")
| project TimeGenerated, Computer, NewProcessName, CommandLine, ParentProcessName
```

> **Remember:** `curl`/`wget` to external IPs = exfiltration. `cloudflared` = tunnel abuse. `rclone` = cloud sync tool frequently abused for data theft.

---

## 💥 Impact

### Ransomware Indicators

| Field | Value |
|---|---|
| **MITRE Technique** | [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) |
| **MITRE Tactic** | Impact |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith "warlock.exe"
| project TimeGenerated, TargetUserName, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated asc
```

> **Remember:** Replace `warlock.exe` with your identified ransomware binary. Look for child processes: `vssadmin`, `bcdedit`.

---

### Recovery Inhibition

| Field | Value |
|---|---|
| **MITRE Technique** | [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) |
| **MITRE Tactic** | Impact |
| **Status** | ✅ Tested |

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("vssadmin delete", "wmic shadowcopy", "bcdedit", "wbadmin delete")
| project TimeGenerated, Computer, NewProcessName, CommandLine, ParentProcessName
```

> **Remember:** `vssadmin delete shadows` = removes Volume Shadow Copies / restore points. `bcdedit /set recoveryenabled No` = disables Windows Recovery Mode.

---

## 📖 Quick Reference — Windows Event IDs

| Event ID | Description | Use Case |
|---|---|---|
| `4624` | Successful logon | Track access, identify external logins |
| `4625` | Failed logon | Brute force / password spray detection |
| `4672` | Special privileges assigned | Admin activity monitoring |
| `4688` | Process creation | Command execution, LOLBins, malware chains |
| `4697` | Service installed (Security log) | Persistence mechanism detection |
| `4720` | Account created | Backdoor account detection |
| `4728` | Added to global group | Privilege escalation monitoring |
| `4769` | Kerberos TGS request | Kerberoasting detection |
| `5145` | Network share access | Lateral movement, enumeration |

---

## 🗺️ MITRE ATT&CK Coverage Summary

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | *(Scoping queries)* | — |
| Initial Access | Valid Accounts: Domain Accounts | T1078.002 |
| Initial Access | Valid Accounts | T1078 |
| Execution | User Execution: Malicious File | T1204.002 |
| Execution | Command and Scripting Interpreter | T1059 |
| Defense Evasion | System Binary Proxy Execution | T1218 |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 |
| Persistence | Create Account: Domain Account | T1136.002 |
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Discovery | Network Share Discovery | T1135 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |
| Impact | Data Encrypted for Impact | T1486 |
| Impact | Inhibit System Recovery | T1490 |

---

*Queries authored for Microsoft Sentinel / Log Analytics using the `SecurityEvent` table. Adjust time ranges, usernames, and hostnames to match your environment.*
