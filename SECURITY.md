# Security Policy

repo นี้เป็น detection content สาธารณะของ ECOP Thailand — เราถือความปลอดภัยของ repo และ supply chain เป็นเรื่องจริงจัง

## รายงานช่องโหว่ / Reporting a vulnerability

ถ้าคุณพบ:
- ข้อมูล sensitive (PII / internal data / credential) ที่หลุดอยู่ใน repo หรือ git history
- rule หรือ Sysmon config ที่อาจถูกใช้ในทางที่เป็นอันตราย
- ปัญหาความปลอดภัยใน CI / workflow / dependency

**กรุณาอย่าเปิด public issue** — รายงานแบบส่วนตัวที่:

- 📧 **security@ecop.co.th** (แทนด้วยอีเมลจริงของทีม)
- หรือผ่าน **GitHub Security Advisory** (แท็บ Security → Report a vulnerability)

เราจะตอบรับภายใน **2 วันทำการ** และแจ้งแนวทางแก้ไขภายใน **7 วัน**

## ขอบเขต / Scope

| ในขอบเขต | นอกขอบเขต |
|---|---|
| ข้อมูลรั่วใน repo/history | false positive ของ rule (ใช้ FP report template แทน) |
| supply-chain (org/CI/dependency) | คำขอ rule ใหม่ (ใช้ rule-request template) |
| malicious content ใน PR | |

## แนวปฏิบัติด้านความปลอดภัยของ repo นี้

มาตรการที่บังคับใช้กับ repo (สำหรับ maintainer):

- ✅ บังคับ **2FA ทั้ง organization** (`ecop-th`)
- ✅ **Branch protection** บน `main`: require PR review, ห้าม force-push, require status checks ผ่าน
- ✅ **Secret scanning** + **push protection** ของ GitHub เปิดใช้งาน
- ✅ **gitleaks** สแกน secret/PII ทั้ง pre-commit และ CI
- ✅ **Dependabot** เปิดสำหรับ GitHub Actions
- ✅ GitHub Actions ใช้ `pull_request` (ไม่ใช่ `pull_request_target`) และ **ไม่ถือ secret** ใน workflow ที่ run จาก fork
- ✅ Maintainer สิทธิ์แบบ least-privilege; แนะนำ signed commits

## Responsible disclosure

เรายินดีให้เครดิตผู้รายงาน (ถ้าต้องการ) ใน release note หลังแก้ไขเสร็จ ขอบคุณที่ช่วยให้ detection content ของชุมชนปลอดภัยขึ้นครับ 🙏
