# Playbook — Log4Shell Exploitation (CVE-2021-44228)

**Rule:** [`et_20211210_cve-2021-44228_log4shell.yml`](../emerging-threats/et_20211210_cve-2021-44228_log4shell.yml)
**Severity:** 🔴 Critical · **ATT&CK:** T1190 (Exploit Public-Facing Application)

---

## สรุปสั้น / TL;DR

มีการส่ง payload `${jndi:ldap://...}` มาที่เว็บแอป → พยายามใช้ช่องโหว่ Log4j ให้เซิร์ฟเวอร์ดึงและรันโค้ดจากภายนอก
ถ้าแอปใช้ Log4j เวอร์ชันที่มีช่องโหว่ = **อาจ RCE สำเร็จ** ต้องตรวจว่าแค่ "ถูกสแกน" หรือ "ถูกเจาะจริง"

---

## 1. Triage (0–15 นาที)

| ตรวจ | คำถาม |
|---|---|
| เป้าหมาย | request เข้า host/endpoint ไหน? เป็นแอป Java ที่ใช้ Log4j หรือไม่ |
| สำเร็จไหม | เซิร์ฟเวอร์มี **outbound connection** ไปยัง IP ใน payload หลังได้รับ request หรือไม่ (ตัวชี้ขาด exploit สำเร็จ) |
| แหล่งที่มา | source IP — scanner ทั่วไป หรือ targeted? |
| เวอร์ชัน | Log4j เวอร์ชันอะไร (< 2.16 เสี่ยง) |

➡️ มี outbound JNDI/LDAP/RMI หลัง request → **ถือว่า compromise + isolate**

## 2. Contain

1. **Block** source IP + payload pattern ที่ WAF/firewall
2. ถ้ายืนยัน RCE → **isolate** host
3. Virtual patch ที่ WAF (กฎจับ `${jndi:`, `${lower:`, obfuscation) เป็นมาตรการชั่วคราว

## 3. Collect evidence

- Web/proxy log ที่มี `${jndi:` (รวม header: User-Agent, X-Forwarded-For, URI)
- Outbound connection log จากเซิร์ฟเวอร์หลัง request (DNS, LDAP 389, RMI 1099)
- Process spawned โดย Java process (`java` → `cmd`/`sh`/`curl`)

## 4. Eradicate & Recover

- **Patch Log4j** เป็นเวอร์ชันปลอดภัย (≥ 2.17.x) — แก้ที่ต้นเหตุ
- ตรวจ webshell / persistence ที่อาจถูกวาง
- หมุน credential/secret ที่อยู่บนเซิร์ฟเวอร์ที่ถูกเจาะ
- Rebuild ถ้ายืนยัน RCE สำเร็จ

## 5. Hunt (ขยายผล)

```spl
index=web ("${jndi:" OR "${lower:" OR "jndi%3a")
| stats count by src_ip, uri, http_user_agent, dest
```

หา Java process ที่ spawn shell/LOLBin หลังเวลาที่ถูกยิง payload + ค้นทุกแอปในองค์กรที่ใช้ Log4j

## 6. หมายเหตุสำหรับลูกค้า (ไทย)

- ถ้า RCE สำเร็จและกระทบข้อมูลส่วนบุคคล → ประเมินแจ้งเหตุตาม **PDPA** ภายใน 72 ชม.
- แม้แค่ "ถูกสแกน" ก็ควรเร่งตรวจ inventory ว่ามีระบบใดใช้ Log4j ที่ยังไม่ patch

---

<sub>ECOP MDR Playbook · ทบทวนล่าสุด 2026-06-02</sub>
