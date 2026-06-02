# 📖 IR Playbooks

คู่มือรับมือ (Incident Response) ภาษาไทย คู่กับ rule — บอกว่า **เมื่อ Alert ดังแล้วต้องทำอะไรต่อ**
โครงสร้าง: TL;DR → Triage → Contain → (Collect/Eradicate) → Hunt → หมายเหตุไทย (PDPA / ธปท.)

> ครอบคลุม rule ระดับ `critical` + `high` ครบทุกตัว (24/30) · rule ระดับ `medium` เป็นทางเลือก เติมภายหลัง

## 🔴 Critical
| Playbook | Rule | ATT&CK |
|---|---|---|
| [LSASS credential dump](lsass_dump_comsvcs.md) | comsvcs MiniDump | T1003.001 |
| [NTDS.dit extraction](ntdsutil_dump.md) | ntdsutil dump | T1003.003 |
| [Log4Shell exploitation](log4shell_cve_2021_44228.md) | CVE-2021-44228 | T1190 |

## 🟠 High — Endpoint / Credential
| Playbook | ATT&CK |
|---|---|
| [Shadow copy deletion (ransomware)](vssadmin_delete_shadows.md) | T1490 |
| [Kerberoasting](kerberoasting.md) | T1558.003 |
| [PsExec lateral movement](psexec_lateral.md) | T1021.002 |
| [PowerShell encoded command](powershell_encoded_command.md) | T1059.001 |
| [Mshta remote payload](mshta_remote_payload.md) | T1218.005 |
| [Certutil download/decode](certutil_download.md) | T1105 |
| [Regsvr32 Squiblydoo](regsvr32_scrobj_remote.md) | T1218.010 |
| [WMIC process call create](wmic_process_call_create.md) | T1047 |
| [Event log cleared](wevtutil_clear_logs.md) | T1070.001 |
| [Office spawning shell (macro)](office_spawning_shell.md) | T1204.002 |
| [LOLBin external connection](lolbin_external_connection.md) | T1071.001 |

## 🟠 High — Web
| Playbook | ATT&CK |
|---|---|
| [Webshell creation](web_webshell_creation.md) | T1505.003 |
| [IIS worker spawning shell](iis_worker_spawning_shell.md) | T1505.003 |
| [SQL injection](web_sql_injection.md) | T1190 |
| [Path traversal / LFI](web_path_traversal_lfi.md) | T1190 |

## 🟠 High — Network / Firewall
| Playbook | ATT&CK |
|---|---|
| [RDP exposed to internet](rdp_inbound_from_internet.md) | T1133 |
| [SMB outbound to internet](smb_outbound_to_internet.md) | T1048 |

## 🟠 High — Cloud (M365 / Azure AD)
| Playbook | ATT&CK |
|---|---|
| [Inbox forwarding (BEC)](m365_inbox_forwarding.md) | T1114.003 |
| [Mailbox forwarding (BEC)](m365_mailbox_forwarding.md) | T1114.003 |
| [MFA disabled](azuread_mfa_disabled.md) | T1556.006 |
| [Privileged role assigned](azuread_privileged_role_assigned.md) | T1098.003 |

---
> อยากเสนอ/ปรับ playbook? ดู [CONTRIBUTING.md](../CONTRIBUTING.md)
