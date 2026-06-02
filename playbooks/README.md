# 📖 IR Playbooks

คู่มือรับมือ (Incident Response) ภาษาไทย คู่กับ rule สำคัญ — บอกว่า **เมื่อ Alert ดังแล้วต้องทำอะไรต่อ**
ทุก playbook มีโครงเดียวกัน: TL;DR → Triage → Contain → Collect → Eradicate → Hunt → หมายเหตุไทย (PDPA / ธปท.)

## รายการ Playbook

| Playbook | Rule | Severity | ATT&CK |
|---|---|---|---|
| [LSASS credential dump](lsass_dump_comsvcs.md) | comsvcs MiniDump | 🔴 Critical | T1003.001 |
| [NTDS.dit extraction](ntdsutil_dump.md) | ntdsutil dump | 🔴 Critical | T1003.003 |
| [Log4Shell exploitation](log4shell_cve_2021_44228.md) | CVE-2021-44228 | 🔴 Critical | T1190 |
| [Shadow copy deletion (ransomware)](vssadmin_delete_shadows.md) | vssadmin delete | 🟠 High | T1490 |
| [Kerberoasting](kerberoasting.md) | kerberoast | 🟠 High | T1558.003 |
| [Webshell creation](web_webshell_creation.md) | webshell in webroot | 🟠 High | T1505.003 |
| [M365 inbox forwarding (BEC)](m365_inbox_forwarding.md) | inbox forwarding rule | 🟠 High | T1114.003 |

> 🔜 เติม playbook ให้ rule `high`/`critical` ที่เหลือเรื่อย ๆ ตามจังหวะรายสัปดาห์
> อยากเสนอ playbook? ดู [CONTRIBUTING.md](../CONTRIBUTING.md)
