# Playbook — Office Spawning a Command Shell (Macro Phishing)

**Rule:** [`proc_creation_win_office_spawning_shell.yml`](../sigma/windows/proc_creation_win_office_spawning_shell.yml)
**Severity:** 🟠 High · **ATT&CK:** T1204.002 (Malicious File)

## TL;DR
โปรแกรม Office (Word/Excel/Outlook) spawn `cmd`/`powershell`/script host — สัญญาณชัดของ **macro มัลแวร์ในเอกสาร phishing** ซึ่งเป็นช่องทาง initial access อันดับต้น ๆ ของแบงก์ไทย

## Triage (0–15 นาที)
- **เอกสาร/ไฟล์แนบ** ชื่ออะไร มาจากอีเมลใคร
- **child process** ทำอะไรต่อ (download? encoded PowerShell?)
- ผู้ใช้เปิดไฟล์จากอีเมล/เว็บไหม

## Contain
1. Isolate host
2. ยึดไฟล์เอกสาร + วิเคราะห์ macro
3. ค้นอีเมลต้นทางใน mail gateway → quarantine ทุกคนที่ได้รับ

## Hunt
```spl
index=sysmon EventCode=1
  ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\outlook.exe","*\\powerpnt.exe")
  Image IN ("*\\cmd.exe","*\\powershell.exe","*\\wscript.exe","*\\mshta.exe")
| stats count by host, User, ParentImage, Image, _time
```

## หมายเหตุไทย
แจ้งเตือนผู้ใช้ทั้งองค์กรเรื่อง phishing campaign · ถ้านำสู่ malware ที่กระทบข้อมูล → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
