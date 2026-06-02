# Playbook — Kerberoasting

**Rule:** [`proc_creation_win_kerberoasting.yml`](../sigma/finance/proc_creation_win_kerberoasting.yml)
**Severity:** 🟠 High · **ATT&CK:** T1558.003 (Kerberoasting)

---

## สรุปสั้น / TL;DR

มีคนขอ Kerberos service ticket ของบัญชีที่มี SPN เพื่อเอาไปแครกรหัสผ่าน **offline** (ไม่ต้องยิงเข้าระบบ ตรวจจับยาก)
เป้าหมายคือ **service account** ในโดเมน — โดยเฉพาะของแบงก์ที่รหัสมักไม่ค่อยเปลี่ยนและตั้งอ่อน

---

## 1. Triage (0–15 นาที)

| ตรวจ | คำถาม |
|---|---|
| Host/User | ใครรัน? เครื่องอะไร? เป็นบัญชีปกติของคนนั้นไหม |
| เครื่องมือ | Rubeus / Invoke-Kerberoast / setspn enumerate ทั้งโดเมน? |
| ขอบเขต | ขอ ticket ของกี่บัญชี? ขอรวดเดียวจำนวนมาก = น่าสงสัยมาก |

➡️ ถ้าเป็นเครื่องมือ offensive (Rubeus) → **incident** (admin ปกติไม่ใช้)

## 2. Contain

1. Isolate host ที่รันเครื่องมือ
2. ระบุ **service account** ที่ถูกขอ ticket → เตรียม reset รหัส (อาจถูกแครกแล้ว)
3. ถ้าบัญชีมีสิทธิ์สูง → จำกัดสิทธิ์ชั่วคราว

## 3. Collect evidence

- Sysmon EID 1 ของเครื่องมือ + command line
- **Security Event 4769** (Kerberos service ticket request) — โดยเฉพาะ encryption type `0x17` (RC4) ที่ขอจำนวนมากจาก source เดียว
- บัญชี SPN ที่ถูก target

## 4. Eradicate & Recover

- **Reset รหัส service account ที่ถูก target** ด้วยรหัสยาว/สุ่ม (25+ ตัว) — กันการแครกสำเร็จ
- เปลี่ยน service account สำคัญให้ใช้ **gMSA** (รหัสหมุนอัตโนมัติ)
- บังคับ AES, ปิด RC4 ที่ทำได้
- ตรวจว่า credential ที่อาจถูกแครกถูกใช้ที่ไหนต่อ

## 5. Hunt (ขยายผล)

```spl
index=sysmon EventCode=1 (CommandLine="*kerberoast*" OR CommandLine="*Rubeus*" OR CommandLine="*asktgs*")
| stats count by host, User, CommandLine, _time
```

เสริมด้วย Event 4769 ที่มี Ticket_Encryption_Type=0x17 + ขอหลาย SPN จาก account เดียวในเวลาสั้น

## 6. หมายเหตุสำหรับลูกค้า (ไทย)

- เป็นขั้น credential access ระหว่างการบุกรุก — มักตามด้วย lateral movement → เร่งหา activity ที่เกี่ยวข้อง
- ถ้านำไปสู่การเข้าถึงข้อมูลส่วนบุคคล → ประเมิน **PDPA**

---

<sub>ECOP MDR Playbook · ทบทวนล่าสุด 2026-06-02</sub>
