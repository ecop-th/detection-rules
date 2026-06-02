# Playbook — RDP Exposed to the Internet

**Rule:** [`net_firewall_rdp_inbound_from_internet.yml`](../sigma/firewall/net_firewall_rdp_inbound_from_internet.yml)
**Severity:** 🟠 High · **ATT&CK:** T1133 (External Remote Services)

## TL;DR
มี RDP (3389) เข้ามาจาก IP ภายนอก/อินเทอร์เน็ต — RDP ที่เปิดสู่เน็ตเป็นช่องทางเข้าของ ransomware อันดับต้น ๆ แทบไม่ควรอนุญาต

## Triage (0–15 นาที)
- **host ปลายทาง** สำคัญแค่ไหน, source IP มาจากไหน
- มี **brute force** (4625 เยอะ) ตามด้วย **logon สำเร็จ** (4624) ไหม
- เป็น VPN/สาขาที่ถูกต้องที่ลืม whitelist หรือไม่

## Contain
1. **ปิด RDP ออกอินเทอร์เน็ต** — บังคับผ่าน VPN/jump host
2. ถ้ามี logon สำเร็จจากภายนอก → isolate + ถือว่า compromise
3. Reset รหัสบัญชีที่ login

## Hunt
```spl
index=firewall dest_port=3389 action=allow
| search NOT src_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
| stats count by src_ip, dest, _time
```
+ จับคู่ Windows 4625/4624 บน host นั้น

## หมายเหตุไทย
ปิด RDP เน็ต + เปิด NLA/MFA · ถ้านำสู่ ransomware/ข้อมูลรั่ว → ประเมิน PDPA + ธปท.

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
