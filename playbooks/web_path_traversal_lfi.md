# Playbook — Path Traversal / LFI

**Rule:** [`web_path_traversal_lfi.yml`](../sigma/web/web_path_traversal_lfi.yml)
**Severity:** 🟠 High · **ATT&CK:** T1190 (Exploit Public-Facing Application)

## TL;DR
พบ pattern directory traversal (`../`, encoded) หรือพยายามอ่านไฟล์ระบบ (`/etc/passwd`, `web.config`) — มักนำสู่การขโมย source/credential หรือ web defacement

## Triage (0–15 นาที)
- **ไฟล์เป้าหมาย** ที่พยายามอ่านคืออะไร
- response code — 200 (อ่านได้!) หรือ 403/404
- targeted หรือ scanner

## Contain
1. Block source IP + WAF rule
2. ถ้าอ่านไฟล์ sensitive สำเร็จ → ถือว่า credential/config รั่ว → หมุน secret
3. แจ้งทีมพัฒนาแก้ input validation

## Hunt
```spl
index=web (c_uri="*../../*" OR c_uri="*%2e%2e%2f*" OR c_uri="*/etc/passwd*" OR c_uri="*web.config*")
| stats count by src_ip, c_uri, status, _time
```

## หมายเหตุไทย
ตรวจหน้าเว็บว่าถูกแก้ (defacement) ไหม · ข้อมูลรั่ว → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
