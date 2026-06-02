# Playbook — PowerShell Encoded Command

**Rule:** [`proc_creation_win_powershell_encoded_command.yml`](../sigma/windows/proc_creation_win_powershell_encoded_command.yml)
**Severity:** 🟠 High · **ATT&CK:** T1059.001 (PowerShell)

## TL;DR
PowerShell ถูกเรียกด้วย `-enc` (base64) เพื่อซ่อนคำสั่งจริง — เทคนิคยอดนิยมใน phishing chain และ post-exploitation

## Triage (0–15 นาที)
- **ถอด base64** ดูว่าคำสั่งจริงทำอะไร (download? IEX? reverse shell?)
- **Parent** อะไรเรียก? (Office/cmd/scheduled task)
- เป็นเครื่องมือ admin/deployment ที่รู้จักไหม

## Contain
1. Isolate host ถ้าคำสั่งที่ถอดได้เป็นอันตราย
2. Block C2/URL ที่พบในคำสั่ง
3. หา persistence/process ที่ถูกสร้างต่อ

## Hunt
```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
  (CommandLine="* -enc *" OR CommandLine="* -encodedcommand*")
| stats count by host, User, ParentImage, _time
```

## หมายเหตุไทย
เปิด PowerShell Script Block Logging (Event 4104) เพื่อเก็บคำสั่งเต็มในอนาคต · กระทบข้อมูล → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
