# Pull Request

## สรุปการเปลี่ยนแปลง
<!-- เพิ่ม rule อะไร / แก้อะไร -->

## ประเภท
- [ ] `add:` rule ใหม่
- [ ] `fix:` แก้ false positive / logic
- [ ] `tune:` ปรับ threshold / filter
- [ ] `docs:` เอกสาร / playbook

## Checklist (ต้องครบก่อน merge)
- [ ] รัน `sigma check sigma/` ผ่านในเครื่องแล้ว
- [ ] rule มี `id` เป็น UUID v4
- [ ] มี **MITRE ATT&CK** tag (`attack.tNNNN`)
- [ ] ใส่ `author` เป็นชื่อ/handle ของตัวเอง
- [ ] `falsepositives` เขียนจากของจริง (ไม่ใช่ "Unknown")
- [ ] เพิ่ม sample log ใน `tests/positive/` (และ `tests/negative/` ถ้ามี)
- [ ] ถ้า `level` เป็น `high`/`critical` → มี playbook ใน `playbooks/`
- [ ] อัปเดต `CHANGELOG.md` (ส่วน Unreleased)

## sample log / หลักฐานว่ายิงโดน
```
<วาง log ที่ rule นี้ควรตรวจจับ>
```
