# Tests — Sample Logs & Validation

ทุก rule ควรมี sample log ที่ "ควรยิงโดน" (true positive) และถ้าเป็นไปได้ ตัวอย่างที่ "ไม่ควรโดน" (true negative)
ไฟล์เหล่านี้ทำให้ reviewer ยืนยันได้ว่า rule ทำงานจริง ไม่ over-match

## โครงสร้าง

```
tests/
├── positive/    # log ที่ rule ควรตรวจจับได้
└── negative/    # log ที่ rule ไม่ควร alert (กัน false positive)
```

ตั้งชื่อไฟล์ให้ตรงกับ rule:
`positive/<rule_id_หรือชื่อ rule>.json`

## วิธี validate ในเครื่อง

```bash
# ตรวจ syntax + schema ของทุก rule
sigma check sigma/

# แปลง rule เป็น query เพื่อดูว่า field ถูกต้อง
sigma convert -t splunk -p sysmon sigma/finance/proc_creation_win_lsass_dump_comsvcs.yml
```

> หมายเหตุ: การ "รัน rule กับ log จริง" แบบ end-to-end ทำผ่าน pipeline ของ SIEM แต่ละค่าย
> sample log ในนี้ใช้เป็นหลักฐานเชิงเอกสารและสำหรับ regression review โดย maintainer
