# ECOP Sysmon Baseline

Sysmon คือแหล่ง telemetry หลักที่ Sigma rule ในระบบ Windows ของ repo นี้พึ่งพา
config ในโฟลเดอร์นี้เป็น **baseline ที่สมดุลระหว่าง coverage กับ noise** สำหรับ enterprise ไทย

## ไฟล์

| ไฟล์ | ใช้เมื่อ |
|---|---|
| `ecop-sysmon-baseline.xml` | ค่าเริ่มต้นที่แนะนำสำหรับ workstation/server ส่วนใหญ่ |

> ฐานของ config นี้ต่อยอดจากแนวทางของ [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
> และ [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular) ปรับ tuning ตาม
> threat ที่ ECOP เจอในภูมิภาค

## ติดตั้ง

```powershell
# ครั้งแรก
sysmon64.exe -accepteula -i ecop-sysmon-baseline.xml

# อัปเดต config (ไม่ต้องถอนติดตั้ง)
sysmon64.exe -c ecop-sysmon-baseline.xml
```

## ก่อน deploy production — อ่านก่อน ⚠️

1. **ทดสอบใน lab ก่อนเสมอ** — EID 3 (network) และ EID 22 (DNS) สร้าง volume สูง ปรับ filter ให้ตรง environment
2. ตรวจ exclusion ให้เข้ากับ EDR/AV ของคุณ กัน event ซ้ำซ้อน
3. หลัง deploy ให้ดู ingest volume เข้า SIEM 24–48 ชม. แล้วค่อย tune
4. config นี้เปิด EID 10 (ProcessAccess) เฉพาะ target สำคัญ (เช่น lsass) เพื่อรองรับ rule credential-access โดยไม่ท่วม

> 📌 ไฟล์ XML baseline จะถูกเพิ่มใน release ถัดไป — เวอร์ชันนี้เป็นโครงและเอกสารแนวทางก่อน
