# 🔄 รับ update อัตโนมัติ / Keeping rules up to date

repo นี้อัปเดต rule ใหม่ตาม threat จริงเป็นประจำ — ด้านล่างคือวิธีให้ SOC ของคุณ
"ดึงของใหม่อัตโนมัติ" โดยไม่ต้องมานั่งเช็กเอง

---

## ฝั่งคนใช้ — 3 ระดับ

### 🟢 ระดับ 1: กด Watch (ง่ายสุด)
กดปุ่ม **Watch → Custom → Releases** ที่หน้า repo
→ ทุกครั้งที่เราออก release รายเดือน คุณจะได้ noti ทันที

### 🟡 ระดับ 2: ตั้ง cron `git pull` (อัตโนมัติเต็มตัว)

ให้เครื่องที่เก็บ rule ดึงของใหม่เองทุกคืน:

```bash
# clone ครั้งแรก
git clone https://github.com/NattapongECOP/detection-rules.git /opt/ecop-rules

# เพิ่มใน crontab (crontab -e) — ดึงทุกวันตี 2
0 2 * * * cd /opt/ecop-rules && git pull --quiet
```

### 🟣 ระดับ 3: auto-convert เข้า SIEM (ครบวงจร)

ดึง + แปลงเป็น query ของ SIEM อัตโนมัติในสคริปต์เดียว:

```bash
#!/usr/bin/env bash
# /opt/ecop-rules/sync.sh — ตั้ง cron รันทุกคืน
set -e
cd /opt/ecop-rules
git pull --quiet

# แปลงทุก rule เป็น query ของ SIEM ที่คุณใช้ (ตัวอย่าง: Splunk)
mkdir -p /opt/ecop-rules/_compiled
for rule in $(find sigma emerging-threats -name '*.yml'); do
  out="/opt/ecop-rules/_compiled/$(basename "${rule%.yml}").spl"
  sigma convert -t splunk "$rule" > "$out" 2>/dev/null || true
done
echo "synced + compiled $(date)"
```

```bash
# crontab: รันทุกวันตี 2
0 2 * * * /opt/ecop-rules/sync.sh >> /var/log/ecop-rules-sync.log 2>&1
```

> 💡 อยาก pin เวอร์ชันให้นิ่ง? ใช้ `git checkout vYYYY.MM` (tag รายเดือน) แทน `git pull`
> แล้วค่อยอัปเดต tag เมื่อทดสอบ rule ใหม่ใน lab เสร็จ

---

## ฝั่งเรา (ECOP) — repo อัปเดตตัวเองยังไง

| กลไก | ทำอะไร |
|---|---|
| `update-stats.yml` | อัปเดต badge จำนวน rule อัตโนมัติเมื่อมี rule ใหม่ |
| `monthly-release.yml` | ออก GitHub Release ทุกวันที่ 1 ของเดือน (สรุป rule ใหม่) |
| Scheduled rule review | ทีม ECOP เติม rule ใหม่ตาม CVE/threat ที่ฮอตเป็นประจำ |

→ คนใช้แค่ `git pull` ก็ได้ของใหม่ทั้งหมด
