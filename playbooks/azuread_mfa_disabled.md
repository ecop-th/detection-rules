# Playbook — Azure AD MFA / Strong Auth Disabled

**Rule:** [`azuread_mfa_method_disabled.yml`](../sigma/m365/azuread_mfa_method_disabled.yml)
**Severity:** 🟠 High · **ATT&CK:** T1556.006 (Multi-Factor Authentication)

## TL;DR
มีการปิด MFA หรือลบ authentication method ใน Azure AD / Entra ID — attacker ทำหลังยึดบัญชีเพื่อคงการเข้าถึงไว้ (identity defense-evasion)

## Triage (0–15 นาที)
- **ใคร**ปิด MFA ของ**ใคร**
- เป็น helpdesk reset ตามคำขอที่ถูกต้องไหม (มี ticket?)
- บัญชีผู้กระทำมี sign-in ผิดปกติก่อนหน้าไหม

## Contain
1. **เปิด MFA กลับทันที** สำหรับบัญชีที่ถูกปิด
2. Reset + revoke session ของบัญชีที่ถูกกระทบ และของผู้กระทำถ้าสงสัย
3. ตรวจสิทธิ์ของบัญชีผู้กระทำ

## Hunt
```
Azure AD Audit Log — Operation contains:
  "Disable Strong Authentication" OR "Delete authentication method"
→ จับคู่กับ risky sign-in / IP แปลก
```

## หมายเหตุไทย
MFA tampering = สัญญาณบัญชีถูกยึด → ตรวจ activity ทั้งหมดของบัญชีนั้น · ข้อมูลรั่ว → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
