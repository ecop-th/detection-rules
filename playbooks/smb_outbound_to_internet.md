# Playbook — SMB Outbound to the Internet

**Rule:** [`net_firewall_smb_outbound_to_internet.yml`](../sigma/firewall/net_firewall_smb_outbound_to_internet.yml)
**Severity:** 🟠 High · **ATT&CK:** T1048 (Exfiltration Over Alternative Protocol)

## TL;DR
มี SMB (445/139) ออกไปยังปลายทางอินเทอร์เน็ต — SMB ควรอยู่ภายในเท่านั้น การออกเน็ตบ่งชี้ data exfil, การบังคับ authentication (ขโมย NTLM hash) หรือ misconfig

## Triage (0–15 นาที)
- **host ต้นทาง → dest IP** ภายนอกตัวไหน
- ปริมาณข้อมูลที่ออก (exfil?) 
- มี link/ไฟล์ที่ชี้ไป UNC ภายนอก (forced auth) ไหม

## Contain
1. **Block 445/139 outbound** ที่ firewall (ควรเป็น default)
2. Isolate host ต้นทาง
3. ถือว่า NTLM credential ของ host/ผู้ใช้อาจรั่ว → reset

## Hunt
```spl
index=firewall (dest_port=445 OR dest_port=139) action=allow
| search NOT dest_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
| stats sum(bytes_out) by src_ip, dest_ip, _time
```

## หมายเหตุไทย
ปิด SMB outbound ทั้งองค์กร · ถ้ามีข้อมูลถูก exfil → ประเมิน PDPA ภายใน 72 ชม.

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
