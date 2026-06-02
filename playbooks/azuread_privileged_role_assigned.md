# Playbook — Azure AD Privileged Role Assignment

**Rule:** [`azuread_privileged_role_assigned.yml`](../sigma/m365/azuread_privileged_role_assigned.yml)
**Severity:** 🟠 High · **ATT&CK:** T1098.003 (Additional Cloud Roles)

## TL;DR
มีบัญชีถูกเพิ่มเข้าบทบาทสิทธิ์สูงใน Azure AD (เช่น Global Administrator) — attacker มอบสิทธิ์ให้ตัวเองเพื่อคุม tenant อย่างถาวร

## Triage (0–15 นาที)
- **ใคร**เพิ่ม**ใคร**เข้า role อะไร
- มี change/ticket รองรับการมอบสิทธิ์ admin ไหม
- บัญชีผู้กระทำ + บัญชีที่ได้รับสิทธิ์ มี sign-in ผิดปกติไหม

## Contain
1. ถ้าไม่ได้รับอนุญาต → **ถอด role ออกทันที**
2. Reset + revoke session ของบัญชีที่ได้รับสิทธิ์ และผู้กระทำ
3. ตรวจการเปลี่ยนแปลงอื่นที่บัญชีนั้นทำ (app registration, conditional access)

## Hunt
```
Azure AD Audit Log — Operation: "Add member to role" / "Add eligible member to role"
Role: Global Administrator / Privileged Role Administrator / Security Administrator
```

## หมายเหตุไทย
priv role = คุม tenant ได้ → ถ้าไม่ชอบมาพากล ถือเป็น incident ร้ายแรง · ข้อมูลรั่ว → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
