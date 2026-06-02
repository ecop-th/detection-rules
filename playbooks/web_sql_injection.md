# Playbook — SQL Injection Attempt

**Rule:** [`web_sql_injection_patterns.yml`](../sigma/web/web_sql_injection_patterns.yml)
**Severity:** 🟠 High · **ATT&CK:** T1190 (Exploit Public-Facing Application)

## TL;DR
พบ pattern SQL injection ใน web request (UNION SELECT, `or 1=1`, xp_cmdshell) — พยายามเจาะฐานข้อมูลผ่านเว็บแอป มักเป็น recon ก่อนดึงข้อมูล

## Triage (0–15 นาที)
- **endpoint/parameter** ไหนถูกยิง
- เป็นการ scan อัตโนมัติ หรือ targeted (manual)
- มีสัญญาณ**สำเร็จ**ไหม (response ใหญ่ผิดปกติ, error SQL, data ออก)

## Contain
1. Block source IP + virtual patch ที่ WAF
2. ถ้าสงสัยสำเร็จ → ตรวจ DB log + จำกัดสิทธิ์ DB account ของแอป
3. แจ้งทีมพัฒนาแก้ parameterized query

## Hunt
```spl
index=web (c_uri="*union*select*" OR c_uri="*or 1=1*" OR c_uri="*xp_cmdshell*" OR c_uri="*information_schema*")
| stats count by src_ip, c_uri, status, _time
```

## หมายเหตุไทย
เว็บแบงก์/รัฐเป็นเป้าหลัก · ถ้าข้อมูลส่วนบุคคลรั่ว → ประเมินแจ้ง PDPA ภายใน 72 ชม.

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
