---
name: False Positive Report
about: แจ้งว่า rule ของเรา alert ผิด (เจอ benign activity)
title: "[FP] <rule id หรือชื่อ rule>"
labels: false-positive
---

## Rule ที่เกี่ยวข้อง
<!-- ใส่ rule id หรือ path เช่น sigma/finance/proc_creation_win_lsass_dump_comsvcs.yml -->

## พฤติกรรมที่ทำให้ alert (แต่จริง ๆ ไม่อันตราย)
<!-- อธิบายว่าอะไรเป็นตัวจุด alert -->

## ตัวอย่าง log (ลบข้อมูล sensitive ออกก่อน)
```
<วาง log ที่ sanitize แล้ว>
```

## environment
- SIEM / backend:
- product/version ที่เกี่ยวข้อง:

## ข้อเสนอแนะ filter (ถ้ามี)
<!-- เช่น "ควร exclude Image ที่ลงท้ายด้วย \\our-backup-agent.exe" -->
