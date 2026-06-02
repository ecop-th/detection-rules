# Playbook — Event Log Cleared (Anti-Forensics)

**Rule:** [`proc_creation_win_wevtutil_clear_logs.yml`](../sigma/windows/proc_creation_win_wevtutil_clear_logs.yml)
**Severity:** 🟠 High · **ATT&CK:** T1070.001 (Clear Windows Event Logs)

## TL;DR
มีการล้าง Windows event log (`wevtutil cl` หรือ `Clear-EventLog`) — เทคนิคทำลายหลักฐาน (anti-forensics) ที่แทบไม่มีเหตุผล legitimate

## Triage (0–15 นาที)
- **ใคร/host ไหน** ล้าง log อะไร (Security? System?)
- มี change/ticket รองรับไหม → ถ้าไม่มี = น่าสงสัยมาก
- มี activity น่าสงสัยอื่นก่อนหน้าไหม (attacker มักล้างหลังลงมือ)

## Contain
1. **เก็บ snapshot/forward log ที่เหลือทันที** (กันถูกล้างเพิ่ม)
2. Isolate host ถ้ายืนยันว่าไม่ใช่ admin ปกติ
3. ตรวจ Event 1102 (audit log cleared) / 104

## Hunt
```spl
index=sysmon EventCode=1 ((Image="*\\wevtutil.exe" CommandLine="* cl *")
  OR CommandLine="*Clear-EventLog*")
| stats count by host, User, CommandLine, _time
```

## หมายเหตุไทย
การลบหลักฐานบ่งชี้การบุกรุกที่ลงมือแล้ว → ยกระดับสืบสวน · ตั้ง log forwarding ไป SIEM กันถูกล้างที่เครื่อง

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
