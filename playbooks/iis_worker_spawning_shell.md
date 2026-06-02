# Playbook — IIS Worker Spawning a Shell (Webshell Execution)

**Rule:** [`proc_creation_win_iis_worker_spawning_shell.yml`](../sigma/web/proc_creation_win_iis_worker_spawning_shell.yml)
**Severity:** 🟠 High · **ATT&CK:** T1505.003 (Web Shell)

## TL;DR
`w3wp.exe` (หรือ httpd/php/tomcat) spawn `cmd`/`powershell` — สัญญาณชัดว่ามี **webshell กำลังถูกรัน** บนเซิร์ฟเวอร์ (ขั้น active exploitation)

## Triage (0–15 นาที)
- **คำสั่ง** ที่ web process รันคืออะไร (whoami? net? download?)
- มีไฟล์ webshell ใน webroot ไหม (เชื่อมกับ rule webshell creation)
- request ไหน/source IP ไหน trigger

## Contain
1. **Isolate web server**
2. ยึด webshell + ระบุช่องทางที่ถูกวาง
3. Block source IP

## Hunt
```spl
index=sysmon EventCode=1
  ParentImage IN ("*\\w3wp.exe","*\\httpd.exe","*\\php-cgi.exe","*\\tomcat.exe")
  Image IN ("*\\cmd.exe","*\\powershell.exe","*\\net.exe","*\\whoami.exe")
| stats count by host, ParentImage, Image, CommandLine, _time
```

## หมายเหตุไทย
server โดนยึด = วิกฤต · patch ช่องโหว่ที่ถูกใช้ · ข้อมูลรั่ว → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
