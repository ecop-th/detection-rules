# Threat Actor Mapping

โยง detection rule ในrepo นี้เข้ากับ **เทคนิคที่กลุ่มภัยคุกคามดัง ๆ ใช้บ่อย** — เพื่อให้ทีม SOC เห็นว่าการครอบคลุม (coverage) ของตัวเองสอดคล้องกับ actor ที่เกี่ยวข้องกับภาคการเงิน/อาเซียนแค่ไหน

> ⚠️ **สำคัญ — detection ≠ attribution:** การที่ rule แจ้งเตือน *ไม่ได้* แปลว่าเป็นกลุ่มนั้นจริง
> เทคนิคเหล่านี้ถูกใช้ร่วมกันโดยหลายกลุ่ม การ "ระบุตัวผู้กระทำ" ต้องอาศัยหลักฐานหลายชั้น
> ตารางนี้ใช้เพื่อ **วางแผน coverage และ threat hunting** ไม่ใช่เพื่อชี้ตัวคนร้าย

## วิธี map ในrepo นี้

เราใช้ **ATT&CK Group ID เป็น tag** ใน rule ที่เกี่ยวข้อง เช่น:

```yaml
tags:
  - attack.t1003.001
  - attack.g0032   # Lazarus Group (อ้างอิง MITRE ATT&CK Groups)
```

## กลุ่มที่เกี่ยวข้องกับภาคการเงิน / อาเซียน

| กลุ่ม (ATT&CK ID) | แรงจูงใจ / เป้าหมาย | เทคนิคเด่นที่ repo เราครอบ | rule ที่เกี่ยวข้อง |
|---|---|---|---|
| **Lazarus Group** (G0032) | DPRK · ปล้นเงินธนาคาร (SWIFT), crypto | cred dumping, PowerShell, persistence | `proc_creation_win_lsass_dump_comsvcs`, `proc_creation_win_powershell_encoded_command`, `registry_set_win_run_key_persistence` |
| **APT41** (G0096) | จีน · จารกรรม + การเงิน · active ใน SEA | web exploitation, webshell, lateral | `web_sql_injection_patterns`, `web_webshell_creation_in_webroot`, `proc_creation_win_iis_worker_spawning_shell` |
| **FIN7** (G0046) | การเงินล้วน · POS/banking | Office macro phishing, service persistence | `proc_creation_win_office_spawning_shell`, `proc_creation_win_service_creation_sc` |
| **FIN11 / ransomware ops** | extortion · double extortion | shadow copy deletion, log clearing, lateral | `proc_creation_win_vssadmin_delete_shadows`, `proc_creation_win_wevtutil_clear_logs`, `proc_creation_win_psexec_lateral` |
| **BEC operators** (ทั่วไป) | ฉ้อโกงโอนเงิน · ผ่าน M365 | inbox forwarding, MFA tampering | `m365_exchange_new_inbox_forwarding_rule`, `azuread_mfa_method_disabled` |

## ใช้ตารางนี้ยังไง

1. **Coverage gap analysis** — เลือก actor ที่กังวล → ดูว่าครอบ rule ครบไหม → ถ้าขาด เปิด issue เสนอ rule ใหม่
2. **Threat hunting** — ถ้ามีข่าวกรองว่ากลุ่มหนึ่งกำลัง active ในภูมิภาค → โฟกัสล่า rule กลุ่มนั้นก่อน
3. **รายงานผู้บริหาร** — แปลง coverage เป็นภาษาความเสี่ยง "เราตรวจจับ X% ของเทคนิคที่กลุ่ม Y ใช้"

## อ้างอิง

- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- การ attribution ควรอ้างอิง CTI หลายแหล่ง ไม่ใช่จาก detection เดียว

---

<sub>อัปเดต mapping เมื่อมี actor/campaign ใหม่ที่เกี่ยวข้องกับลูกค้าในภูมิภาค · maintained by ECOP CTI</sub>
