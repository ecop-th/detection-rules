# Playbook — LSASS Credential Dump (comsvcs.dll MiniDump)

**Rule:** [`proc_creation_win_lsass_dump_comsvcs.yml`](../sigma/finance/proc_creation_win_lsass_dump_comsvcs.yml)
**Severity:** 🔴 Critical · **ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)

---

## สรุปสั้น / TL;DR

มีคนพยายาม dump หน่วยความจำของ `lsass.exe` เพื่อขโมย credential โดยใช้ `comsvcs.dll` ที่ติดมากับ Windows
นี่คือสัญญาณ **hands-on-keyboard** — แทบไม่มีเหตุผล legitimate ให้ทีมตอบสนองทันที

---

## 1. Triage (0–15 นาที)

| ตรวจ | คำถาม |
|---|---|
| Host | เครื่องอะไร? เป็น DC / jump host / server การเงินไหม? |
| User | บัญชีที่รันเป็นใคร? เป็น admin หรือ service account? |
| Parent process | อะไรเป็นตัวเรียก rundll32? (cmd / powershell / remote tool?) |
| เวลา | ตรงกับช่วงงานปกติของ admin คนนั้นไหม? |

➡️ ถ้า host เป็น DC หรือ server ที่ถือ credential สำคัญ → **ยกระดับเป็น incident ทันที**

## 2. Contain (15–60 นาที)

1. **Isolate** host ออกจากเครือข่าย (EDR network containment หรือ switch port)
2. อย่าเพิ่ง reboot — เก็บ volatile evidence ก่อน (ดูข้อ 3)
3. ระบุไฟล์ dump output: หา argument หลัง `MiniDump <pid> <ตำแหน่งไฟล์>` ใน command line → ยึดไฟล์นั้น
4. **สมมติว่า credential ทุกตัวบนเครื่องนี้ถูก compromise**

## 3. Collect evidence

- Process creation log เต็ม (Sysmon EID 1) ของ rundll32 + parent chain
- ไฟล์ dump (`.dmp`) ถ้ายังอยู่
- Sysmon EID 10 (ProcessAccess) ที่ target เป็น `lsass.exe` — ยืนยันการเข้าถึง
- Logon events (4624/4625) รอบ ๆ เวลานั้น เพื่อหา lateral movement

## 4. Eradicate & Recover

- **Reset password** ทุกบัญชีที่ login บนเครื่องนี้ โดยเฉพาะ domain admin / service account
- ถ้าเป็น DC → พิจารณา reset **krbtgt** สองรอบ (กัน Golden Ticket)
- หา persistence ที่อาจถูกวางไว้ (scheduled task, service, run key)
- Rebuild host จาก image ที่สะอาดถ้ายืนยัน compromise

## 5. Hunt (ขยายผล)

ค้นทั้ง environment ว่ามี comsvcs MiniDump ที่อื่นอีกไหม:

```spl
index=sysmon EventCode=1 (Image="*\\rundll32.exe")
  CommandLine="*comsvcs*" CommandLine="*MiniDump*"
| stats count by host, User, CommandLine, _time
```

ตรวจ credential ที่ถูกขโมยว่าถูกใช้ที่ไหนต่อ (pass-the-hash, remote logon ผิดปกติ)

## 6. หมายเหตุสำหรับลูกค้า (ไทย)

- ถ้าเข้าข่ายเหตุการณ์ที่กระทบข้อมูลส่วนบุคคล → ประเมินหน้าที่แจ้งเหตุตาม **PDPA** ภายใน 72 ชม.
- ภาคการเงินภายใต้กำกับ ธปท. → พิจารณาเกณฑ์รายงานเหตุการณ์ภัยไซเบอร์ที่เกี่ยวข้อง

---

<sub>ECOP MDR Playbook · ทบทวนล่าสุด 2026-06-01</sub>
