# 🚨 Indicators of Compromise (IOCs)
## Operation PhishHook — AcmeCorp
**Incident ID:** IR-2026-0415-001 | **Date:** 2026-04-15 | **Analyst:** Narmin Fatullayeva

---

## 🌐 Network IOCs

| Type | Value | Context | First Seen |
|------|-------|---------|------------|
| IP | `185.220.101.45` | Attacker recon & phishing origin — GeoIP: Russia, AS47583 | 2026-04-15 09:23 |
| IP | `45.142.212.100` | C2 server — flagged by 14 AV vendors, Netherlands AS47583 | 2026-04-14 22:15 |
| Domain | `update-checker.xyz` | C2 domain & payload hosting — registered 1 day before attack | 2026-04-14 14:23 |
| URL | `http://update-checker.xyz/updates/svc32.exe` | Payload download URL | 2026-04-15 10:22 |
| Port | `443/TCP` to `45.142.212.100` | C2 beaconing over TLS (~60s interval) | 2026-04-15 10:22 |

---

## File IOCs

| Type | Value | Context |
|------|-------|---------|
| SHA256 | `3a9f2c8d1e5b7a4f6c0d2e8b3a7f5c1d9e4b8a2f7c6d3e1b9a5f0c4d7e2b6a8f` | `Invoice_2026_0847.docm` — phishing document |
| SHA256 | `d4c7e2b1a8f5c3e0d7b4a9f2c6e1d8b5a3f0c7e4d2b9a6f3c0e7d4b1a8f5c2e9` | `svc32.exe` — primary implant (245,760 bytes) |
| SHA256 | `f6e9d3c0b7a4f1e8d5c2b9a6f3e0d7c4b1a8f5c2e9d6b3a0f7e4d1c8b5a2f9e6` | `svcbackup.dll` — DC backdoor DLL |
| File | `svc32.exe` | Implant — masquerades as Windows service |
| File | `winhlp32.dat` | Malware config file dropped to `%TEMP%` |
| File | `Invoice_2026_0847.docm` | Macro-enabled phishing document |

### File Paths
| Path | Context |
|------|---------|
| `C:\Users\john.smith\AppData\Roaming\Microsoft\svc32.exe` | Implant on workstation |
| `C:\Users\john.smith\AppData\Local\Temp\winhlp32.dat` | Malware config |
| `C:\Windows\Temp\svc32.exe` | Lateral movement copy on DC |
| `C:\Windows\System32\svcbackup.dll` | Backdoor DLL on DC |

---

## Host IOCs

| Type | Value | Context |
|------|-------|---------|
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate` | Persistence — points to `svc32.exe` |
| Scheduled Task | `\WindowsUpdateHelper` | Persistence — hourly execution of `svc32.exe` |
| Service | `WinRemoteSvc` | Remote execution service installed on DC |
| User Account | `svcbackup01` | Backdoor account — added to Domain Admins |
| WMI Filter | `WindowsUpdateFilter` | Post-reboot persistence on DC |
| WMI Consumer | `WindowsUpdateConsumer` | Paired WMI consumer on DC |
| Process | `svc32.exe` | Malicious implant process |
| Privilege | `SeDebugPrivilege` | Enabled on non-admin process — prereq for lsass dump |

---

## Email IOCs

| Field | Value |
|-------|-------|
| Sender Address | `billing@acmecorp-invoices.com` |
| Sender Domain | `acmecorp-invoices.com` (typosquat — 1 day old) |
| Subject | `URGENT: Overdue Invoice #INV-2026-0847 - Action Required` |
| X-Originating-IP | `185.220.101.45` |
| SPF | ❌ FAIL |
| DKIM | ❌ FAIL |

---

## Hunting Queries

Use these in your SIEM to hunt for related activity:

```
```
# Detect C2 beaconing
dst_ip = "45.142.212.100" AND dst_port = 443

# Detect payload download
url CONTAINS "update-checker.xyz"

# Detect lsass access
process_name = "svc32.exe" AND target_process = "lsass.exe"

# Detect backdoor account
event_id = 4720 AND new_account = "svcbackup01"

# Detect scheduled task creation by standard user
event_id = 4698 AND user NOT IN domain_admins
```

---

*IOC list generated from IR-2026-0415-001 | Narmin Fatullayeva*
