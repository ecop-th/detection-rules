# Playbook — NTDS.dit Extraction via ntdsutil

**Rule:** [`proc_creation_win_ntdsutil_dump.yml`](../sigma/finance/proc_creation_win_ntdsutil_dump.yml)
**Severity:** 🔴 Critical · **ATT&CK:** T1003.003 (OS Credential Dumping: NTDS)

---

## สรุปสั้น / TL;DR

มีคนพยายามดึงไฟล์ `NTDS.dit` (ฐานข้อมูล Active Directory ที่เก็บ **credential ของทุกบัญชีในโดเมน**) ออกมาด้วย `ntdsutil`
ถ้าสำเร็จ = attacker ถือ hash ของทั้งโดเมนไปแครก/ปลอมตัวได้หมด — **นี่คือสถานการณ์ domain compromise ระดับสูงสุด**

---

## 1. Triage (0–15 นาที)

| ตรวจ | คำถาม |
|---|---|
| Host | เป็น Domain Controller ไหม? (ควรเป็น — ntdsutil รันบน DC) |
| User | บัญชีไหน? มีสิทธิ์ Domain/Enterprise Admin หรือไม่ |
| มี change ไหม | มี ticket/แผน promote DC ใหม่รองรับไหม? ถ้า**ไม่มี → incident ทันที** |
| Output | หา path `create full <ตำแหน่ง>` ใน command line → ไฟล์ที่ถูกสร้าง |

➡️ ถ้าไม่มี change รองรับ → **ยกระดับเป็น critical incident + แจ้งผู้บริหารทันที**

## 2. Contain (เร่งด่วน)

1. **Isolate DC** ออกจากเครือข่าย (ระวัง: อย่าทำให้ AD ทั้ง domain ล่ม — ประสานทีม infra)
2. ยึดไฟล์ output (มัก `.dit` + registry hive `SYSTEM`/`SECURITY`) ที่ถูกสร้าง
3. ถือว่า **credential ทั้งโดเมนถูก compromise**

## 3. Collect evidence

- Sysmon EID 1 ของ `ntdsutil.exe` + parent chain
- ไฟล์ IFM output (โฟลเดอร์ที่มี `Active Directory\ntds.dit`, `registry\SYSTEM`)
- Security log 4688/4624 รอบเวลานั้น
- ตรวจการคัดลอกไฟล์ออก (SMB, อุปกรณ์ external, cloud upload)

## 4. Eradicate & Recover

- **Reset krbtgt สองรอบ** (สำคัญสุด — กัน Golden Ticket)
- Reset password ทุก privileged account + service account
- พิจารณา reset ทั้งโดเมน (tiered) ตามขอบเขตที่ยืนยันได้
- ตรวจ persistence / backdoor account ที่อาจถูกสร้าง (DCShadow, AdminSDHolder, GPO แปลก)

## 5. Hunt (ขยายผล)

```spl
index=sysmon EventCode=1 (Image="*\\ntdsutil.exe" OR CommandLine="*create full*")
| stats count by host, User, CommandLine, _time
```

ตรวจเพิ่ม: การใช้ `vssadmin`/`diskshadow` สร้าง shadow copy เพื่อก๊อป NTDS, การ replicate ผิดปกติ (DCSync — Event 4662)

## 6. หมายเหตุสำหรับลูกค้า (ไทย)

- กระทบข้อมูลส่วนบุคคลแน่นอน → ประเมินแจ้งเหตุตาม **PDPA** ภายใน 72 ชม.
- ภาคการเงินภายใต้กำกับ **ธปท.** → เข้าเกณฑ์รายงานเหตุการณ์ภัยไซเบอร์ระดับร้ายแรง

---

<sub>ECOP MDR Playbook · ทบทวนล่าสุด 2026-06-02</sub>
