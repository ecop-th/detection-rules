# Playbook — Webshell Creation in Web Root

**Rule:** [`web_webshell_creation_in_webroot.yml`](../sigma/web/web_webshell_creation_in_webroot.yml)
**Severity:** 🟠 High · **ATT&CK:** T1505.003 (Web Shell)

---

## สรุปสั้น / TL;DR

มีไฟล์ script (.aspx/.php/.jsp) ถูกเขียนลง web root โดยกระบวนการที่ไม่ใช่ deploy tool — เป็นสัญญาณว่ามีคนวาง **webshell**
เพื่อควบคุมเซิร์ฟเวอร์จากระยะไกล มักนำไปสู่ web defacement หรือใช้เป็นฐานบุกต่อ

---

## 1. Triage (0–15 นาที)

| ตรวจ | คำถาม |
|---|---|
| ไฟล์ | ชื่อ/ตำแหน่งไฟล์? เปิดดูเนื้อหา — มี `eval`, `Request`, `cmd` ไหม |
| ผู้สร้าง | process อะไรเขียนไฟล์? (w3wp, cmd, unknown?) ผ่าน deploy ปกติไหม |
| ช่องเข้า | มาจากไหน — upload function, exploit, ช่องโหว่ CMS? |

➡️ ถ้ายืนยันเป็น webshell → **incident** + ตรวจว่ามันถูกเรียกใช้แล้วหรือยัง

## 2. Contain

1. **ยึด/quarantine ไฟล์ webshell** (เก็บสำเนาเป็นหลักฐานก่อนลบ)
2. ถ้าถูกเรียกใช้แล้ว (มี child process จาก w3wp) → **isolate server**
3. Block source IP ที่ติดต่อ webshell ที่ WAF/firewall

## 3. Collect evidence

- Sysmon EID 11 (FileCreate) ของไฟล์ webshell + ผู้สร้าง
- Web access log — request ที่เรียกไฟล์ webshell (POST + parameter น่าสงสัย)
- Sysmon EID 1 — `w3wp.exe`/`httpd` spawn `cmd`/`powershell` (ดู rule IIS worker spawning shell)
- เนื้อหาไฟล์ webshell (ชนิด/ความสามารถ)

## 4. Eradicate & Recover

- ลบ webshell ทุกตัว (อาจมีหลายไฟล์/หลาย path)
- **แก้ช่องทางเข้า** — patch ช่องโหว่/แก้ upload function ที่ถูกใช้วาง
- ตรวจ persistence เพิ่ม (scheduled task, service, บัญชีใหม่)
- หมุน credential/secret บนเซิร์ฟเวอร์

## 5. Hunt (ขยายผล)

```spl
index=sysmon EventCode=11 (TargetFilename="*\\wwwroot\\*" OR TargetFilename="*\\htdocs\\*")
  (TargetFilename="*.aspx" OR TargetFilename="*.php" OR TargetFilename="*.jsp")
| search NOT Image="*\\msdeploy.exe"
| stats count by host, Image, TargetFilename, _time
```

ค้นเว็บเซิร์ฟเวอร์อื่นด้วย pattern เดียวกัน + YARA scan ไฟล์ในทุก webroot

## 6. หมายเหตุสำหรับลูกค้า (ไทย)

- เว็บภาครัฐ/องค์กรไทยเป็นเป้า web defacement บ่อย — ตรวจหน้าเว็บว่าถูกแก้ไขหรือไม่
- ถ้าเข้าถึงข้อมูลส่วนบุคคล → ประเมินแจ้ง **PDPA** ภายใน 72 ชม.

---

<sub>ECOP MDR Playbook · ทบทวนล่าสุด 2026-06-02</sub>
