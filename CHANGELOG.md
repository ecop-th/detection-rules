# Changelog

ทุก release เราจะสรุปว่า "เดือนนี้ ship อะไรเพื่อรับมือ threat อะไร" เพื่อให้ทีม SOC ที่ติดตามเห็นคุณค่าได้ทันที

รูปแบบอ้างอิง [Keep a Changelog](https://keepachangelog.com/)

## [Unreleased]

### Added — ขยาย coverage เป็น 30 rules
**firewall/ (3)** — `net_firewall_rdp_inbound_from_internet` (T1133), `net_firewall_smb_outbound_to_internet` (T1048), `net_firewall_outbound_uncommon_c2_port` (T1571)
**network/EDR (2)** — `dns_query_win_suspicious_tld` (T1071.004), `net_connection_win_lolbin_external_connection` (T1071.001)
**m365/ (4)** — inbox forwarding rule + mailbox forwarding (T1114.003), Azure AD MFA disabled (T1556.006), privileged role assigned (T1098.003)
**emerging-threats/ (1)** — `et_20211210_cve-2021-44228_log4shell` (ตัวอย่าง CVE จริง)
**threat-actors/** — mapping doc: rule → กลุ่ม APT (Lazarus, APT41, FIN7, ransomware ops, BEC)

## [0.1.0] — 2026-06-01 · เปิดตัว 🎉

**Focus: ภาคการเงิน (finance) + web/gov defacement — ตรง customer base ของ ECOP**
**20 rules ครอบ ATT&CK kill chain (initial access → impact)**

### Added — Sigma rules (20)

**finance/ (8)**
- 🟥 `proc_creation_win_lsass_dump_comsvcs` — LSASS dump ผ่าน comsvcs.dll (T1003.001) + playbook
- 🟥 `proc_creation_win_ntdsutil_dump` — ดึง NTDS.dit ทั้งโดเมน (T1003.003)
- 🟧 `proc_creation_win_kerberoasting` — ขโมย service account ticket (T1558.003)
- 🟧 `proc_creation_win_psexec_lateral` — lateral movement แบบ PsExec (T1021.002)
- 🟧 `proc_creation_win_office_spawning_shell` — macro phishing เปิด shell (T1204.002)
- 🟧 `proc_creation_win_powershell_encoded_command` — PowerShell -enc (T1059.001)
- 🟧 `proc_creation_win_vssadmin_delete_shadows` — สัญญาณ ransomware (T1490)
- 🟧 `proc_creation_win_wevtutil_clear_logs` — ล้าง event log (T1070.001)

**web/ (4)**
- 🟧 `web_webshell_creation_in_webroot` — เขียน webshell ลง webroot (T1505.003)
- 🟧 `proc_creation_win_iis_worker_spawning_shell` — webshell ทำงานจริง (T1505.003)
- 🟧 `web_sql_injection_patterns` — SQL injection (T1190)
- 🟧 `web_path_traversal_lfi` — path traversal / LFI (T1190)

**windows/ (8)**
- 🟧 `proc_creation_win_mshta_remote_payload` — mshta remote payload (T1218.005)
- 🟧 `proc_creation_win_certutil_download` — certutil download/decode (T1105)
- 🟧 `proc_creation_win_regsvr32_scrobj_remote` — Squiblydoo (T1218.010)
- 🟧 `proc_creation_win_wmic_process_call_create` — wmic exec/lateral (T1047)
- 🟨 `proc_creation_win_bitsadmin_download` — BITS transfer (T1197)
- 🟨 `proc_creation_win_schtasks_persistence` — scheduled task (T1053.005)
- 🟨 `proc_creation_win_service_creation_sc` — สร้าง service (T1543.003)
- 🟨 `registry_set_win_run_key_persistence` — Run key persistence (T1547.001)

### Added — รองรับ
- 📖 Playbook: LSASS credential dump (TH/EN)
- 🛠 Sysmon baseline guidance + deployment notes
- 🧪 Test scaffolding: positive/negative sample logs
- ⚙️ CI: sigma-cli validation + metadata lint + secret scan บนทุก PR
- 🔒 Data-handling rules + gitleaks (กันข้อมูลลูกค้าหลุด)

### เป้าหมาย v0.2
- เติม rule เดือนละ 1–2 ตัวตาม threat จริง
- เพิ่ม playbook ให้ rule critical ที่เหลือ (ntdsutil, ransomware)
- เปิด `good first rule` issues ให้ชุมชน
