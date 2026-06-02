# Playbook — PsExec Lateral Movement

**Rule:** [`proc_creation_win_psexec_lateral.yml`](../sigma/finance/proc_creation_win_psexec_lateral.yml)
**Severity:** 🟠 High · **ATT&CK:** T1021.002 (SMB/Admin Shares)

## TL;DR
พบสัญญาณ PsExec (`PSEXESVC.exe` หรือ command line เฉพาะ) — การรันโค้ดบนเครื่องอื่นจากระยะไกล มักใช้กระจายตัวในเครือข่ายแบงก์หลังขโมย credential

## Triage (0–15 นาที)
- **เครื่องต้นทาง → ปลายทาง** คู่ไหน
- **บัญชี** ที่ใช้ — admin/service account?
- ทีม IT ใช้ PsExec บริหารปกติ หรือเป็น attacker

## Contain
1. Isolate ทั้งเครื่องต้นทางและปลายทาง
2. ระบุคำสั่ง/ไฟล์ที่ถูกรันบนปลายทาง
3. Reset credential ที่ใช้ (สงสัยถูกขโมย)

## Hunt
```spl
index=sysmon EventCode=1 (Image="*\\PSEXESVC.exe"
  OR (CommandLine="*psexec*" CommandLine="*accepteula*" CommandLine="* -s *"))
| stats count by host, User, ParentImage, _time
```

## หมายเหตุไทย
lateral movement = อยู่กลาง kill chain → เร่งหาขอบเขตที่กระจายไป · ข้อมูลรั่ว → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
