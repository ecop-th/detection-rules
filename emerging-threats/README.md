# Emerging Threats

detection ที่ออกอย่างรวดเร็วเพื่อตอบ **CVE หรือ campaign ที่กำลัง active** — เป้าหมาย SLA: ภายใน **48 ชั่วโมง** หลังมีหลักฐานสาธารณะที่เชื่อถือได้

## ต่างจาก `sigma/` ทั่วไปอย่างไร

| | `sigma/` | `emerging-threats/` |
|---|---|---|
| รอบเวลา | tune จนนิ่งแล้วค่อย merge | เร็วก่อน ปรับทีหลัง |
| status | มัก `stable` | มัก `experimental` |
| FP tolerance | ต่ำ | ยอมสูงกว่าได้ชั่วคราว |

rule ในนี้จะมี comment ระบุ campaign/CVE และวันที่ออก เมื่อ rule นิ่งแล้วจะย้ายเข้าโฟลเดอร์ sector ที่เหมาะสม

## ตั้งชื่อ

`et_<YYYYMMDD>_<cve-หรือ-campaign>_<short>.yml`
เช่น `et_20260601_cve-2026-1234_exchange_rce.yml`

## วิธีทำงาน (ภายใน ECOP)

1. CTI team เห็น signal (KEV, vendor advisory, in-the-wild report)
2. เขียน detection draft + sample IOC/log
3. peer review เร็ว (1 คน) → merge เป็น `experimental`
4. แนบลิงก์ rule นี้ใน Cyber News Alert / Vulnerability Alert ที่ส่งลูกค้า
5. เก็บ feedback จากสนาม → tune → ย้ายเข้า `sigma/`
