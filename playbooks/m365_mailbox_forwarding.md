# Playbook — M365 Mailbox-Level Forwarding

**Rule:** [`m365_exchange_mailbox_forwarding_configured.yml`](../sigma/m365/m365_exchange_mailbox_forwarding_configured.yml)
**Severity:** 🟠 High · **ATT&CK:** T1114.003 (Email Forwarding Rule)

## TL;DR
มีการตั้ง SMTP forwarding ระดับ mailbox (`Set-Mailbox` + ForwardingSmtpAddress) — ตั้งโดย admin หรือผ่าน admin creds ที่ถูกขโมย ก๊อปเมลทั้งกล่องไปให้ attacker เงียบ ๆ (BEC)

## Triage (0–15 นาที)
- **mailbox** ใครถูกตั้ง, ปลายทางเป็นโดเมน**ภายนอก**ไหม
- **ผู้ตั้ง** เป็น admin จริง + มี ticket ไหม
- มี sign-in admin ผิดปกติก่อนหน้าไหม

## Contain
1. ลบ forwarding ที่เป็นอันตราย
2. Reset + revoke session ของ admin/บัญชีที่ถูกใช้
3. ปิด external auto-forwarding ทั้ง tenant

## Hunt
```
Unified Audit Log — Operation: Set-Mailbox
Parameters contains: ForwardingSmtpAddress OR DeliverToMailboxAndForward
→ จับคู่กับ risky sign-in ในช่วงเดียวกัน
```

## หมายเหตุไทย
BEC = เสี่ยงการเงินสูง แจ้งฝ่ายการเงิน · ข้อมูลในเมลรั่ว → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
