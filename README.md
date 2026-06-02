# ECOP Detection Rules

> Open-source detection content for SOC teams in Thailand & ASEAN.
> Sigma rules · Sysmon config · IR playbooks — mapped to MITRE ATT&CK, tested, bilingual (ไทย / English).

[![Sigma CI](https://github.com/ecop-th/detection-rules/actions/workflows/sigma-test.yml/badge.svg)](https://github.com/ecop-th/detection-rules/actions/workflows/sigma-test.yml)
[![License: DRL 1.1](https://img.shields.io/badge/license-DRL%201.1-blue.svg)](LICENSE)
![Rules](https://img.shields.io/badge/dynamic/json?label=rules&query=%24.count&url=https%3A%2F%2Fraw.githubusercontent.com%2Fecop-th%2Fdetection-rules%2Fmain%2F.stats.json)

---

## ทำไมต้อง repo นี้ / Why this repo

มี [SigmaHQ](https://github.com/SigmaHQ/sigma) ที่ครอบคลุม detection ระดับโลกอยู่แล้ว — repo นี้ **ไม่ได้มาแข่ง** แต่มาเติมในจุดที่ของระดับโลกมองไม่เห็น:

- 🇹🇭 **Threat landscape ไทย/อาเซียนจริง** — campaign ที่ลงมือกับแบงก์ โรงพยาบาล และภาครัฐในภูมิภาคนี้ (web defacement, Thai-targeted phishing, banking malware, mule-account behavior)
- 🌏 **Bilingual ที่ใช้งานได้จริง** — ทุก rule มี playbook ภาษาไทยพร้อม context เชิงปฏิบัติ ไม่ใช่แค่แปลคำ
- ⚡ **Emerging-threat SLA** — เมื่อมี campaign/CVE สำคัญ เราตั้งเป้าออก detection ภายใน **48 ชั่วโมง** ใน [`emerging-threats/`](emerging-threats/)
- ✅ **Tested, ไม่ใช่แค่เขียนทิ้ง** — ทุก rule ผ่าน `sigma-cli` validation + มี false-positive note

Maintained by the **ECOP MDR / CTI team**. ใช้กับ SOC ของคุณได้เลย ฟรี ภายใต้ [Detection Rule License](LICENSE).

---

## โครงสร้าง / Repository layout

```
ecop-detection-rules/
├── sigma/                  # Sigma detection rules
│   ├── finance/            # sector: ธนาคาร / การเงิน
│   ├── web/                # webshell, defacement, web attack
│   ├── windows/            # endpoint / LOLBin / credential access (EDR telemetry)
│   ├── network/            # dns_query / network_connection (EDR-fed)
│   ├── firewall/           # firewall log: RDP/SMB/C2 ports
│   └── m365/               # Microsoft 365 / Azure AD (cloud audit log)
├── sysmon/                 # ECOP Sysmon baseline config (modular)
├── playbooks/              # IR playbook ต่อ rule (TH / EN)
├── emerging-threats/       # detection ตอบ CVE/campaign ใหม่ ภายใน 48 ชม. (เช่น Log4Shell)
├── threat-actors/          # mapping: rule → กลุ่ม APT (ATT&CK Groups)
├── tests/                  # sample logs + วิธี validate rule
└── .github/                # CI, issue & PR templates
```

> 💡 **EDR rules อยู่ที่ไหน?** rule ใน `windows/` (process_creation) และ `network/` (network_connection,
> dns_query) คือ EDR telemetry — EDR เป็น "แหล่ง log" ไม่ใช่ rule แยกประเภท

แต่ละ rule ตั้งชื่อตาม convention ของ SigmaHQ:
`<logsource>_<product>_<short_description>.yml` เช่น `proc_creation_win_mshta_remote_payload.yml`

---

## เข้ามาแล้วต้องทำอะไร? / How to use this repo

> 💡 **เข้าใจก่อน 1 ข้อ:** repo นี้ **ไม่ใช่โปรแกรมที่โหลดมาติดตั้ง** — มันคือ "ตำราสูตรตรวจจับ"
> คุณเอา **rule (สูตร)** ไปแปลงเป็น query แล้ววางใน SIEM ของคุณเอง ของที่เอาไปใช้จริงคือ
> *query ที่แปลงจาก Sigma* ไม่ใช่ตัวไฟล์ที่ต้องรัน

### เลือกวิธีเอาไปใช้ — มี 3 แบบ

| แบบ | ทำยังไง | เหมาะกับ |
|---|---|---|
| 🟢 **ง่ายสุด** | เปิดไฟล์ `.yml` ที่อยากได้ → กดปุ่ม **Copy** มุมขวาบน (ไม่ต้องโหลดไฟล์) | มาลองครั้งแรก เอา rule เดียว |
| 🟡 **กลาง** | กดปุ่มเขียว **`<> Code` → Download ZIP** ได้ทุก rule | อยากได้ทั้งชุด |
| 🟣 **จริงจัง** | `git clone` แล้ว `git pull` รับ update รายเดือนอัตโนมัติ | ทีม SOC ที่ใช้ต่อเนื่อง |

### 4 ขั้น จากเข้ามา → ตั้ง alert ได้จริง

```
1. เลือก rule ที่เกี่ยวกับคุณ (เช่น โฟลเดอร์ sigma/finance/)
        │
2. กด Copy / Download  หรือ  git clone ทั้ง repo
        │
3. แปลงเป็น query ของ SIEM ที่คุณใช้  →  sigma convert -t splunk <rule>
        │
4. เอา query ไปวางใน SIEM → กด "Save as Alert" → จบ
        │
   (พอ alert ดัง → เปิด playbooks/ ดูขั้นตอนรับมือต่อ)
```

> 📌 **ไม่รู้จะเริ่มยังไง?** ทำตาม [Quick start](#เริ่มใช้งาน--quick-start) ด้านล่างได้เลย — แค่ 2 คำสั่ง

---

## เริ่มใช้งาน / Quick start

```bash
# 1. ติดตั้ง sigma-cli
pip install sigma-cli

# 2. แปลง rule เป็น query ของ SIEM ที่คุณใช้ (ตัวอย่าง: Splunk)
sigma convert -t splunk -p sysmon sigma/web/web_webshell_creation_in_webroot.yml

# backend อื่นที่รองรับ: elasticsearch, microsoft365defender, qradar, sentinel ฯลฯ
sigma plugin list
```

ใช้ Sysmon config ของเราเป็น baseline:

```bash
# ดูหมายเหตุก่อน deploy ใน sysmon/README.md
sysmon64.exe -accepteula -i sysmon/ecop-sysmon-baseline.xml
```

---

## คุณภาพมาก่อนปริมาณ / Quality bar

เรายอมมี rule น้อยแต่ดี — ทุก rule ต้อง:

1. ผ่าน `sigma-cli check` (syntax + schema)
2. map กับ **MITRE ATT&CK** อย่างน้อย 1 technique
3. มี `level` + `falsepositives` ที่เขียนจากของจริง
4. มี sample log ใน [`tests/`](tests/) ที่ rule ควร "ยิงโดน"
5. มี playbook คู่กันใน [`playbooks/`](playbooks/) สำหรับ rule ระดับ `high`/`critical`

ดูวิธีเขียนและส่ง PR ที่ [CONTRIBUTING.md](CONTRIBUTING.md)

---

## อยากมีส่วนร่วม / Contributing

เปิดรับ contribution จากชุมชน SOC ไทยและภูมิภาค — ดู issue ที่ติดป้าย
[`good first rule`](https://github.com/ecop-th/detection-rules/labels/good%20first%20rule) เพื่อเริ่ม

เจอ false positive จาก rule ของเรา? เปิด issue ด้วย template
[False Positive Report](.github/ISSUE_TEMPLATE/false_positive.md) ได้เลย — feedback แบบนี้มีค่ามาก

---

## License

Detection content อยู่ภายใต้ **Detection Rule License (DRL) 1.1** — ใช้ ดัดแปลง และนำไป deploy ใน environment ของคุณได้อย่างอิสระ ดู [LICENSE](LICENSE)

---

<sub>Built & maintained by ECOP Thailand — MDR · SOC · CTI. รายงานปัญหาหรือ false positive ผ่าน GitHub Issues</sub>
