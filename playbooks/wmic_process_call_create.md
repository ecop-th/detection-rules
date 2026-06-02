# Playbook — WMIC Process Call Create

**Rule:** [`proc_creation_win_wmic_process_call_create.yml`](../sigma/windows/proc_creation_win_wmic_process_call_create.yml)
**Severity:** 🟠 High · **ATT&CK:** T1047 (Windows Management Instrumentation)

## TL;DR
`wmic process call create` ถูกใช้รัน process — ทั้งแบบ local และ **remote (/node:)** สำหรับ execution และ lateral movement โดยไม่ต้องวางเครื่องมือ

## Triage (0–15 นาที)
- มี **`/node:`** ชี้ไปเครื่องอื่นไหม → สัญญาณ lateral movement
- คำสั่งที่สั่งรันคืออะไร
- บัญชี/host ต้นทางปกติไหม

## Contain
1. Isolate host ต้นทาง (และปลายทางถ้า /node:)
2. ระบุคำสั่งที่ถูกสั่งรัน → ตามไปที่เครื่องปลายทาง
3. Reset credential ที่ใช้ ถ้าสงสัยถูกขโมย

## Hunt
```spl
index=sysmon EventCode=1 Image="*\\wmic.exe"
  CommandLine="*process*" CommandLine="*call*" CommandLine="*create*"
| stats count by host, User, CommandLine, _time
```

## หมายเหตุไทย
lateral movement มักตามหลัง credential theft → ตรวจ logon ผิดปกติ · กระทบข้อมูล → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
