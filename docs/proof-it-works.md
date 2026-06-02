# 🔬 พิสูจน์ว่า rule ใช้ได้จริง / Proof it works

เอกสารนี้แสดงหลักฐานว่า rule ในrepo นี้ **(1) จับ log จริงได้ถูกต้อง** และ **(2) แปลงเป็น query ของ SIEM ได้จริง** — ไม่ใช่แค่ไฟล์ YAML ที่เขียนทิ้งไว้

---

## 1. ทุก rule ผ่าน behaviour test (จับของจริง ไม่ false positive)

แต่ละ rule มี sample log 2 แบบใน [`tests/`](../tests/):
- **positive** — log ที่เป็นการโจมตีจริง → rule ต้อง **MATCH**
- **negative** — log ที่เป็นกิจกรรมปกติ → rule ต้อง **NO MATCH**

รันเองได้ด้วย:
```bash
python tests/run_tests.py
```

ผลลัพธ์จริง (รันใน CI ทุก push):
```
  [PASS ✅] positive proc_creation_win_lsass_dump_comsvcs       got=MATCH     want=MATCH
  [PASS ✅] positive proc_creation_win_kerberoasting            got=MATCH     want=MATCH
  [PASS ✅] positive proc_creation_win_mshta_remote_payload     got=MATCH     want=MATCH
  [PASS ✅] positive proc_creation_win_powershell_encoded_...   got=MATCH     want=MATCH
  [PASS ✅] positive proc_creation_win_vssadmin_delete_shadows  got=MATCH     want=MATCH
  [PASS ✅] positive web_webshell_creation_in_webroot           got=MATCH     want=MATCH
  [PASS ✅] negative ... (ทุกตัว got=NO MATCH)
  รวม: 12 ผ่าน, 0 ไม่ผ่าน
```

> 👉 negative test สำคัญพอ ๆ กับ positive — มันพิสูจน์ว่า rule **ไม่ alert มั่ว** เช่น
> `vssadmin list shadows` (ปกติ) ไม่โดน แต่ `vssadmin delete shadows /all` (ransomware) โดน

---

## 2. rule เดียว → ใช้ได้ทุก SIEM (พิสูจน์ portability)

ตัวอย่าง: [`proc_creation_win_lsass_dump_comsvcs.yml`](../sigma/finance/proc_creation_win_lsass_dump_comsvcs.yml)
แปลงด้วย `sigma convert` ได้ query ของจริงที่ **ก๊อปไปวางใน SIEM ได้ทันที**:

### 🔵 Splunk (SPL)
```bash
sigma convert -t splunk -p sysmon sigma/finance/proc_creation_win_lsass_dump_comsvcs.yml
```
```spl
Image="*\\rundll32.exe" OR OriginalFileName="RUNDLL32.EXE" CommandLine="*comsvcs*" CommandLine="*MiniDump*"
```

### 🟡 Elasticsearch (Lucene)
```bash
sigma convert -t lucene -p sysmon sigma/finance/proc_creation_win_lsass_dump_comsvcs.yml
```
```
(Image:*\\rundll32.exe OR OriginalFileName:RUNDLL32.EXE) AND (CommandLine:*comsvcs* AND CommandLine:*MiniDump*)
```

### 🟠 Elasticsearch (ES|QL)
```bash
sigma convert -t esql -p sysmon sigma/finance/proc_creation_win_lsass_dump_comsvcs.yml
```
```
from * | where (ends_with(Image, "\\rundll32.exe") or OriginalFileName=="RUNDLL32.EXE")
  and CommandLine like "*comsvcs*" and CommandLine like "*MiniDump*"
```

> backend อื่นที่รองรับ: `qradar` (AQL), `eql`, `crowdstrike`, `sentinelone`, `cortexxdr` ฯลฯ
> ดูทั้งหมด: `sigma list targets`

---

## สรุป

| คำถาม | คำตอบ | หลักฐาน |
|---|---|---|
| rule จับภัยจริงได้ไหม? | ✅ ได้ | `tests/run_tests.py` — positive MATCH |
| alert มั่วไหม? | ✅ ไม่ | negative NO MATCH ทุกตัว |
| ใช้กับ SIEM ของฉันได้ไหม? | ✅ ได้ทุกค่าย | `sigma convert` → SPL / Lucene / ES\|QL / AQL ... |

**ก๊อป rule → `sigma convert` → วางใน SIEM → ตั้ง alert → จบ**
