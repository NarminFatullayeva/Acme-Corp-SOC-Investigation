reports/IR_Report_ACMECORP_20260415.md

#  Incident Response Report
## Operation PhishHook — AcmeCorp Network Compromise

| Field | Details |
|-------|---------|
| **Report Date** | April 16, 2026 |
| **Analyst** | Narmin Fatullayeva |
| **Title** | SOC Analyst — Threat Intelligence & Incident Response |
| **Incident ID** | IR-2026-0415-001 |
| **Status** | Contained — Remediation Pending |

---

## 1. Executive Summary

On April 15, 2026, AcmeCorp's network was compromised through a targeted
spear-phishing campaign. The attacker delivered a macro-enabled Word document
which executed a multi-stage payload resulting in full domain compromise.
The attacker achieved persistence, established C2 communications, dumped
domain credentials, moved laterally to the Domain Controller and File Server,
created a privileged backdoor account, and exfiltrated confidential financial
data. Total dwell time: **~55 minutes**.

### Affected Systems

| Host | IP Address | Role | Compromised |
|------|-----------|------|-------------|
| ACME-WS-042 | 10.10.1.42 | User Workstation | ✅ Yes |
| ACME-SRV-DC01 | 10.10.1.10 | Domain Controller | ✅ Yes |
| ACME-SRV-FS01 | 10.10.1.20 | File Server | ✅ Yes |

> **Data Exfiltrated:** `Q1_2026_Revenue_Report.xlsx` — 4.78 MB transferred to C2 server.

---

## 2. Incident Timeline

| Time (UTC) | Event |
|-----------|-------|
| 2026-04-14 14:23 | Threat intel flags `update-checker.xyz` as newly registered C2 domain |
| 2026-04-14 22:15 | Threat intel flags `45.142.212.100` as known C2 hosting IP |
| 2026-04-15 09:23 | Attacker begins web reconnaissance against ACME-WEB-01 |
| 2026-04-15 09:27 | Nikto scanner executed; path traversal attempt returns HTTP 200 |
| 2026-04-15 09:31 | Brute-force login attempts via python-requests against /login |
| 2026-04-15 09:33 | IDS triggers port scan alert from `185.220.101.45` |
| 2026-04-15 10:15 | Phishing email delivered; SPF/DKIM fail; AV returns clean |
| 2026-04-15 10:22 | User opens `Invoice_2026_0847.docm`; macro executes |
| 2026-04-15 10:22 | `svc32.exe` downloaded and executed; C2 check-in established |
| 2026-04-15 10:25 | Registry RunKey + Scheduled Task persistence established |
| 2026-04-15 10:31 | C2 beaconing begins (~60s interval to `45.142.212.100:443`) |
| 2026-04-15 11:00 | `lsass.exe` accessed — credential dump performed |
| 2026-04-15 11:02 | Lateral movement to Domain Controller via stolen credentials |
| 2026-04-15 11:05 | Backdoor account `svcbackup01` created — added to Domain Admins |
| 2026-04-15 11:10 | Lateral movement to File Server; `Financials$` share accessed |
| 2026-04-15 11:11 | **4.78 MB exfiltrated** to C2 server — confirmed data theft |
| 2026-04-15 11:20 | WMI event subscription created for post-reboot persistence |

---

## 3. Technical Analysis

### 3.1 Reconnaissance
Source `185.220.101.45` (GeoIP: Russia, AS47583) performed systematic
probing including Nikto scanning, path traversal attempts, and brute-force
login attempts before pivoting to phishing delivery.

### 3.2 Delivery

| Field | Value |
|-------|-------|
| Sender | `billing@acmecorp-invoices.com` |
| Recipient | `john.smith@acmecorp.com` |
| Attachment | `Invoice_2026_0847.docm` |
| SHA256 | `3a9f2c8d1e5b7a4f6c0d2e8b3a7f5c1d9e4b8a2f7c6d3e1b9a5f0c4d7e2b6a8f` |
| SPF / DKIM | ❌ FAIL / ❌ FAIL |
| Sender Domain Age | 1 day (typosquat) |

### 3.3 Exploitation — Process Chain
```
WINWORD.EXE (PID: 4832)
  └── cmd.exe (PID: 5124)
        └── powershell.exe (PID: 5248) [-EncodedCommand]
              └── svc32.exe (PID: 5376) ← downloaded from C2
```

### 3.4 Persistence Mechanisms
- **Registry RunKey:** `HKCU\...\Run\WindowsUpdate` → `svc32.exe`
- **Scheduled Task:** `WindowsUpdateHelper` — hourly execution
- **WMI Subscription:** `WindowsUpdateFilter` on DC (post-reboot)

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Reconnaissance | T1595.002 | Active Scanning |
| Initial Access | T1566.001 | Spearphishing Attachment |
| Execution | T1059.001 | PowerShell |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Persistence | T1547.001 | Registry Run Keys |
| Persistence | T1053.005 | Scheduled Task |
| Credential Access | T1003.001 | LSASS Memory |
| Lateral Movement | T1078.002 | Valid Accounts: Domain Accounts |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |
| C2 | T1071.001 | Web Protocols |

---

## 5. Indicators of Compromise (IOCs)

### Network
| Type | Value | Context |
|------|-------|---------|
| IP | `185.220.101.45` | Attacker recon / phishing origin |
| IP | `45.142.212.100` | C2 server |
| Domain | `update-checker.xyz` | C2 domain / payload hosting |

### File
| Type | Value | Context |
|------|-------|---------|
| SHA256 | `3a9f2c8d...` | `Invoice_2026_0847.docm` |
| SHA256 | `d4c7e2b1...` | `svc32.exe` — implant |
| Path | `C:\Users\john.smith\AppData\Roaming\Microsoft\svc32.exe` | Implant |
| Path | `C:\Windows\System32\svcbackup.dll` | DC backdoor |

### Host
| Type | Value | Context |
|------|-------|---------|
| Registry | `HKCU\...\Run\WindowsUpdate` | Persistence |
| Task | `WindowsUpdateHelper` | Persistence |
| Account | `svcbackup01` | Backdoor Domain Admin |

---

## 6. Detection Gaps

| Gap | Recommendation |
|-----|----------------|
| TI not actioned | Automate TI feed → firewall/proxy blocklist |
| Email gateway bypass | Quarantine on SPF/DKIM fail + new sender domain |
| Macro execution allowed | Block macros from internet-sourced documents via GPO |
| C2 beaconing undetected | Implement beacon detection on connection regularity |
| NTLM lateral movement | Alert on NTLM auth from workstations to DCs |

---

## 7. Remediation

**Priority 1 — Contain**
- Isolate ACME-WS-042, ACME-SRV-DC01, ACME-SRV-FS01
- Block `45.142.212.100` and `update-checker.xyz` at firewall/DNS
- Disable backdoor account `svcbackup01`
- Reset passwords for `adm_backup` and `john.smith`

**Priority 2 — Eradicate**
- Remove `svc32.exe`, registry key, scheduled task, WMI subscriptions
- Remove `WinRemoteSvc` from DC
- Delete `svcbackup.dll` from `C:\Windows\System32\`
- Full EDR scan across all domain-joined hosts

**Priority 3 — Recover**
- Restore from pre-April 15 known-good backups
- Force domain-wide password reset
- Audit all Domain Admin memberships

---

## 8. Conclusion

This incident represents a complete attack chain from reconnaissance to
data exfiltration in under 55 minutes. The attacker demonstrated clear
pre-planning and operational security. **Critical finding:** with
`svcbackup01` in Domain Admins and WMI persistence on the DC, full
remediation requires a domain rebuild or complete credential reset protocol.

---
*— End of Report — IR-2026-0415-001 —*
