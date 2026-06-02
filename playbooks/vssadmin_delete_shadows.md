# Playbook — Shadow Copy Deletion (Ransomware Precursor)

**Rule:** [`proc_creation_win_vssadmin_delete_shadows.yml`](../sigma/windows/proc_creation_win_vssadmin_delete_shadows.yml)
**Severity:** 🔴 High · **ATT&CK:** T1490 (Inhibit System Recovery)

---

## สรุปสั้น / TL;DR

มีการลบ Volume Shadow Copy ทั้งหมด — เป็นขั้นตอนที่ ransomware เกือบทุกตระกูลทำ **ทันทีก่อนเข้ารหัสไฟล์** เพื่อไม่ให้เหยื่อกู้คืนได้
ถือว่านี่คือ **นาทีทอง** — ถ้ารับมือเร็วอาจหยุดการเข้ารหัสได้ทัน

---

## 1. Triage (0–10 นาที — เร็วที่สุด!)

| ตรวจ | คำถาม |
|---|---|
| Host | เครื่องอะไร? server ไฟล์/DB สำคัญไหม |
| Parent | อะไรเรียก vssadmin? (script, ransomware binary, PsExec?) |
| สัญญาณร่วม | มีการ disable AV, ลบ backup, เข้ารหัสไฟล์เริ่มแล้วหรือยัง |

➡️ **อย่ารอ** — ถือเป็น ransomware ที่กำลังจะลงมือ ดำเนินการ contain ทันที

## 2. Contain (เร่งด่วนสุด)

1. **Isolate host ทันที** (EDR containment) — กันการแพร่และการเข้ารหัส
2. ตัดการเข้าถึง file share / backup จากเครื่องนี้
3. ถ้าหลายเครื่องโดนพร้อมกัน → สงสัย deployment ผ่าน GPO/PsExec/PDQ → **isolate เป็นกลุ่ม**
4. ปกป้อง backup (offline/immutable) ทันที

## 3. Collect evidence

- Sysmon EID 1 ของ `vssadmin`/`wmic` + parent process
- ไฟล์ ransom note (`.txt`/`.html` ในโฟลเดอร์)
- นามสกุลไฟล์ที่ถูกเปลี่ยน (ชี้ตระกูล ransomware)
- เส้นทางเข้ามา (initial access) — RDP, phishing, exploit

## 4. Eradicate & Recover

- ยืนยันขอบเขตเครื่องที่ถูกเข้ารหัส
- กู้คืนจาก **backup ที่สะอาด/offline** เท่านั้น (อย่าจ่ายค่าไถ่)
- หา + ลบ persistence และบัญชีที่ถูกใช้
- Reset credential ที่เกี่ยวข้อง

## 5. Hunt (ขยายผล)

```spl
index=sysmon EventCode=1 ((Image="*\\vssadmin.exe" CommandLine="*delete*" CommandLine="*shadows*")
  OR (Image="*\\wmic.exe" CommandLine="*shadowcopy*" CommandLine="*delete*"))
| stats count by host, User, ParentImage, _time
```

ตรวจเครื่องอื่นที่มี pattern เดียวกัน + การ disable recovery (`bcdedit`, `wbadmin delete`)

## 6. หมายเหตุสำหรับลูกค้า (ไทย)

- Ransomware = เหตุการณ์ร้ายแรง → ประเมินแจ้ง **PDPA** ภายใน 72 ชม. + พิจารณาแจ้งหน่วยงานที่เกี่ยวข้อง
- ภาคการเงิน/โครงสร้างพื้นฐานสำคัญ → เข้าเกณฑ์รายงาน **ธปท. / สกมช.**

---

<sub>ECOP MDR Playbook · ทบทวนล่าสุด 2026-06-02</sub>
