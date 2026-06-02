# Contributing to ECOP Detection Rules

ขอบคุณที่สนใจช่วยกันทำ detection content ให้ SOC ในภูมิภาคนี้แข็งแรงขึ้นครับ 🙏
เอกสารนี้อธิบายวิธีเขียน rule ที่ผ่านมาตรฐานของเรา และวิธีส่ง Pull Request

---

## หลักการ / Philosophy

> **คุณภาพ > ปริมาณ.** rule เดียวที่ทำให้ SOC ของคนอื่น alert ท่วมเพราะ false positive ทำลายความน่าเชื่อถือมากกว่าการไม่มี rule นั้นเลย

ทุก rule ที่ merge เข้า `main` ต้อง:

1. ✅ ผ่าน `sigma-cli check` (syntax + schema) — CI จะ block ถ้าไม่ผ่าน
2. 🎯 map กับ **MITRE ATT&CK** อย่างน้อย 1 technique (`tags`)
3. ⚠️ มี `falsepositives` ที่เขียนจากประสบการณ์จริง ไม่ใช่ "Unknown"
4. 🧪 มี sample log ใน `tests/` ที่ rule นี้ควรตรวจจับได้
5. 📖 ถ้าเป็น `level: high` หรือ `critical` ต้องมี playbook คู่กันใน `playbooks/`

---

## โครงสร้างของ Sigma rule ที่เราต้องการ

ดูตัวอย่างจริงที่ผ่านมาตรฐานได้ที่ [`sigma/web/web_webshell_creation_in_webroot.yml`](sigma/web/web_webshell_creation_in_webroot.yml)

field ที่ **บังคับ**:

| field | หมายเหตุ |
|---|---|
| `title` | สั้น ชัด < 80 ตัวอักษร |
| `id` | UUID v4 (รัน `python -c "import uuid; print(uuid.uuid4())"`) |
| `status` | `experimental` สำหรับ rule ใหม่ → `stable` หลังผ่านสนามจริง |
| `description` | อธิบายว่าจับอะไร และทำไมถึงน่าสงสัย |
| `references` | ลิงก์ advisory / report / blog ที่อ้างอิง |
| `author` | **ใส่ชื่อจริงหรือ handle ของคุณ** — นี่คือ portfolio ของคุณ |
| `date` | `YYYY-MM-DD` |
| `tags` | ต้องมี `attack.<tactic>` และ `attack.tNNNN` |
| `logsource` | ระบุ `category`/`product`/`service` ให้ถูก |
| `detection` | selection + condition |
| `falsepositives` | list ของจริง |
| `level` | `informational` / `low` / `medium` / `high` / `critical` |

field เสริมเฉพาะ repo นี้ (ใส่ใน `tags` แบบ custom prefix):
- `ecop.sector.finance` / `ecop.sector.healthcare` / `ecop.sector.gov`
- `ecop.region.th` / `ecop.region.asean`

---

## 🔒 Data Handling — อ่านก่อนเขียน sample log (สำคัญที่สุด)

> ความเสี่ยงอันดับ 1 ของ public detection repo **ไม่ใช่** การโดน hack — แต่คือ **ข้อมูลลูกค้า/internal หลุดติดไปกับ rule หรือ sample log** แล้วลบไม่ออกเพราะมันอยู่ใน git history ถาวร

### ❌ ห้ามขึ้น repo เด็ดขาด
- **Raw log ของลูกค้า** — แม้แต่ชิ้นเดียว ต้อง sanitize ก่อนเสมอ
- Hostname / internal IP จริง (`10.x`, `172.16–31.x`, `192.168.x`), internal domain (`*.corp`, `*.local`, `*.ad`)
- ชื่อจริง / อีเมล / เลขบัตรประชาชน / เบอร์โทร ของบุคคล (PII ตาม PDPA)
- ชื่อลูกค้า ชื่อระบบภายใน path จริง credential ทุกชนิด (แม้หมดอายุแล้ว)
- 🚫 **ชื่อแบรนด์/บริษัท/keyword ที่ลูกค้าจ้างเฝ้าระวัง (DRP/brand-monitoring)** — ห้ามใส่ใน public rule เด็ดขาด
  - เหตุผล: brand-monitoring/DRP ของเจ้าของแบรนด์อาจเจอชื่อตัวเองใน repo เรา → **ดูเป็นภาพลบ** + เปิดเผยความสัมพันธ์ลูกค้า
  - public rule ใช้ได้แค่ **placeholder / โทเคนทั่วไป** (เช่น `examplebank`, `promptpay`) — ของจริงเก็บใน **private fork / XIPHER DRP**
- detection ที่ผูกกับ **active IR ที่ยังไม่ปิดเคส** — รอปิดเคสก่อน

### ✅ ใช้ค่า placeholder เหล่านี้แทน
| ของจริง | ใช้แทนด้วย |
|---|---|
| hostname/domain | `FIN-DC01.corp.example.co.th` |
| IP (documentation) | `192.0.2.x`, `198.51.100.x`, `203.0.113.x` (RFC 5737) |
| ชื่อบุคคล / user | `CORP\nattapong`, ชื่อสมมติ |
| อีเมล | `someone@example.co.th` |

### กลไกป้องกัน (อัตโนมัติ)
- ติดตั้ง pre-commit hook **ก่อนเริ่มเขียน**: `pip install pre-commit && pre-commit install`
- ทุก commit จะถูกสแกนด้วย **gitleaks** (secret + PII + internal IP/domain) — ถ้าเจอ จะ block ไม่ให้ commit
- CI สแกนซ้ำทั้ง history อีกชั้น

> ⚠️ **ถ้าเผลอ commit ข้อมูล sensitive ไปแล้ว** การลบไฟล์เฉย ๆ ไม่พอ — มันยังอยู่ใน history
> ให้แจ้ง maintainer ทันที เราจะ `git filter-repo` ล้างประวัติ (และถือว่าข้อมูลนั้น compromised แล้ว)

---

## ขั้นตอนส่ง PR

```bash
# 1. fork + clone
git clone https://github.com/<you>/detection-rules.git
cd detection-rules

# 2. ตั้ง dev env
pip install -r requirements-dev.txt   # sigma-cli, pyyaml, pytest

# 3. สร้าง branch
git checkout -b rule/webshell-aspx-china-chopper

# 4. เขียน rule + sample log ใน tests/

# 5. validate ในเครื่องก่อน push
make check          # = sigma-cli check + yaml lint + ทดสอบ sample log
# หรือรันตรง ๆ:
sigma check sigma/

# 6. commit ด้วย convention
git commit -m "add: detect China Chopper webshell in IIS webroot"

# 7. เปิด PR — template จะ checklist ให้เอง
```

### Commit message convention

| prefix | ใช้เมื่อ |
|---|---|
| `add:` | rule ใหม่ |
| `fix:` | แก้ false positive / logic |
| `tune:` | ปรับ threshold / filter |
| `docs:` | แก้ playbook / README |

---

## การ review

- maintainer ของ ECOP จะ review ภายใน ~3 วันทำการ
- เราอาจขอ sample log เพิ่มเพื่อยืนยันว่า rule ยิงโดนจริงและไม่ over-match
- rule ที่ดีแต่ยัง `experimental` ก็ merge ได้ — เราจะเลื่อนเป็น `stable` เมื่อมีหลักฐานจากสนาม

---

## ผู้เริ่มต้น / New to detection engineering?

มองหา issue ป้าย **`good first rule`** — เป็นโจทย์ที่ scope ชัด เหมาะกับการลองทำชิ้นแรก
ถ้า contribution ของคุณเข้าตา เราอยากชวนคุยเรื่องร่วมงานกับ ECOP ด้วยนะครับ 😉

มีคำถาม? เปิด [Discussion](https://github.com/ecop-th/detection-rules/discussions) ได้เลย
