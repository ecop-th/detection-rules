# Playbook — Mshta Remote Payload

**Rule:** [`proc_creation_win_mshta_remote_payload.yml`](../sigma/windows/proc_creation_win_mshta_remote_payload.yml)
**Severity:** 🟠 High · **ATT&CK:** T1218.005 (Mshta)

## TL;DR
`mshta.exe` โหลด payload จาก URL ภายนอก — มักเป็นขั้น stage ของ phishing chain เพื่อดึงมัลแวร์ตัวจริงมารัน

## Triage (0–15 นาที)
- **Parent** อะไรเรียก mshta? (Outlook/Word = มาจาก phishing)
- **URL** ใน command line ชี้ไปไหน? domain มีชื่อเสียงไหม
- เครื่องมี outbound ไป URL นั้นสำเร็จหรือยัง

## Contain
1. Isolate host ถ้ายืนยันว่ารัน payload แล้ว
2. Block URL/domain ที่ proxy/firewall
3. หา process ลูกที่ถูก spawn ต่อ (PowerShell, dropper)

## Hunt
```spl
index=sysmon EventCode=1 Image="*\\mshta.exe" (CommandLine="*http*" OR CommandLine="*javascript:*")
| stats count by host, User, ParentImage, CommandLine, _time
```

## หมายเหตุไทย
มักเริ่มจาก phishing — เตือนผู้ใช้ + ตรวจอีเมลต้นทาง · กระทบข้อมูลส่วนบุคคล → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
