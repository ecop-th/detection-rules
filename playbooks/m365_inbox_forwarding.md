# Playbook — M365 Inbox Forwarding (BEC Indicator)

**Rule:** [`m365_exchange_new_inbox_forwarding_rule.yml`](../sigma/m365/m365_exchange_new_inbox_forwarding_rule.yml)
**Severity:** 🟠 High · **ATT&CK:** T1114.003 (Email Forwarding Rule)

---

## สรุปสั้น / TL;DR

มีการตั้งกฎ forward/redirect อีเมลออกไปยังปลายทางภายนอก — เป็นพฤติกรรมคลาสสิกหลัง **Business Email Compromise (BEC)**
attacker ตั้งกฎลับ ๆ เพื่อแอบอ่านเมลเหยื่อต่อเนื่อง (เช่น ดักจังหวะโอนเงิน/ใบแจ้งหนี้ปลอม) — กระทบการเงินโดยตรง

---

## 1. Triage (0–15 นาที)

| ตรวจ | คำถาม |
|---|---|
| กล่อง | เมลใครถูกตั้งกฎ? เป็นผู้บริหาร/ฝ่ายการเงิน/จัดซื้อไหม (เป้าหมาย BEC) |
| ปลายทาง | forward ไปโดเมน**ภายนอก**องค์กรหรือไม่ |
| ผู้ตั้ง | เจ้าของกล่องตั้งเอง หรือมี sign-in ผิดปกติก่อนหน้า |
| sign-in | มี login จากต่างประเทศ / impossible travel / IP แปลกไหม |

➡️ forward ไปโดเมนภายนอกที่เจ้าตัวไม่ได้ตั้ง → **ถือว่าบัญชีถูก compromise**

## 2. Contain

1. **ลบกฎ forwarding** ที่เป็นอันตราย
2. **Reset รหัส + revoke session** ของบัญชีที่ถูกยึด (force sign-out ทุก device)
3. เปิด/บังคับ **MFA** ถ้ายังไม่มี
4. ตรวจ OAuth app / mailbox delegation ที่ถูกเพิ่ม

## 3. Collect evidence

- Unified Audit Log: `New-InboxRule`/`Set-InboxRule`/`Set-Mailbox` พร้อม parameter (ForwardTo/RedirectTo)
- Sign-in log ของบัญชี (IP, ประเทศ, device, ผลลัพธ์)
- เมลที่ถูก forward ออกไปแล้ว (ขอบเขตข้อมูลรั่ว)
- กฎ/delegation อื่นที่อาจถูกตั้งเพิ่ม

## 4. Eradicate & Recover

- ยืนยันว่าลบกฎ + เพิกถอน session ครบ
- ตรวจบัญชีอื่นในองค์กรว่ามีกฎ forwarding ลักษณะเดียวกันไหม (attacker มักทำหลายกล่อง)
- ปิด **external auto-forwarding** ทั้ง tenant (มาตรการเชิงป้องกัน)
- แจ้งเตือนฝ่ายการเงิน/คู่ค้า ถ้าเสี่ยงถูกหลอกโอนเงิน

## 5. Hunt (ขยายผล)

ค้น Unified Audit Log ทั้ง tenant:
```
Operation: New-InboxRule OR Set-Mailbox
Parameters contains: ForwardTo OR RedirectTo OR ForwardingSmtpAddress
```
จับคู่กับ sign-in ผิดปกติ (risky sign-in / ต่างประเทศ) ในช่วงเดียวกัน

## 6. หมายเหตุสำหรับลูกค้า (ไทย)

- BEC = ความเสี่ยงทางการเงินสูง → แจ้งฝ่ายการเงินให้ระวัง invoice/บัญชีปลายทางที่เปลี่ยน
- ข้อมูลในเมลรั่ว → ประเมินแจ้ง **PDPA** ภายใน 72 ชม.

---

<sub>ECOP MDR Playbook · ทบทวนล่าสุด 2026-06-02</sub>
