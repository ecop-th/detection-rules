# Playbook — Regsvr32 Remote Scriptlet (Squiblydoo)

**Rule:** [`proc_creation_win_regsvr32_scrobj_remote.yml`](../sigma/windows/proc_creation_win_regsvr32_scrobj_remote.yml)
**Severity:** 🟠 High · **ATT&CK:** T1218.010 (Regsvr32)

## TL;DR
`regsvr32` โหลด scriptlet (.sct) จากระยะไกลผ่าน scrobj.dll (เทคนิค Squiblydoo) เพื่อรันโค้ดโดยเลี่ยง application allow-listing

## Triage (0–15 นาที)
- **URL** ของ scriptlet ชี้ไปไหน
- **Parent** อะไรเรียก regsvr32
- เครื่องดึง/รัน scriptlet สำเร็จไหม

## Contain
1. Block URL ปลายทาง
2. Isolate host ถ้ารัน scriptlet แล้ว
3. หา process/persistence ที่ถูกสร้างต่อ

## Hunt
```spl
index=sysmon EventCode=1 Image="*\\regsvr32.exe"
  (CommandLine="*scrobj*" OR CommandLine="*/i:http*" OR CommandLine="*.sct*")
| stats count by host, User, CommandLine, _time
```

## หมายเหตุไทย
เทคนิค bypass — มักเป็นส่วนของ intrusion ที่ใหญ่กว่า ตรวจ activity รอบข้าง · กระทบข้อมูล → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
