# Playbook — Certutil Download / Decode Abuse

**Rule:** [`proc_creation_win_certutil_download.yml`](../sigma/windows/proc_creation_win_certutil_download.yml)
**Severity:** 🟠 High · **ATT&CK:** T1105 (Ingress Tool Transfer)

## TL;DR
`certutil.exe` ถูกใช้ดึงไฟล์จากภายนอก (urlcache) หรือถอด base64 — LOLBin ที่ใช้ stage มัลแวร์โดยแฝงเป็นเครื่องมือ certificate

## Triage (0–15 นาที)
- **URL/ไฟล์** ที่ดึงมาคืออะไร เก็บไว้ path ไหน
- **Parent** อะไรเรียก certutil
- เป็นการดึง CRL/cert ปกติ หรือดึง executable

## Contain
1. Block URL ปลายทาง
2. ยึด/quarantine ไฟล์ที่ถูกดาวน์โหลด/ถอดรหัส
3. Isolate ถ้าไฟล์ถูกรันต่อ

## Hunt
```spl
index=sysmon EventCode=1 Image="*\\certutil.exe"
  (CommandLine="*urlcache*" OR CommandLine="*-decode*" OR CommandLine="*verifyctl*")
| stats count by host, User, CommandLine, _time
```

## หมายเหตุไทย
ตรวจไฟล์ปลายทางด้วย AV/YARA · ถ้านำไปสู่ malware ที่กระทบข้อมูล → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
