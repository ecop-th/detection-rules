# Playbook — LOLBin External Connection (C2)

**Rule:** [`net_connection_win_lolbin_external_connection.yml`](../sigma/network/net_connection_win_lolbin_external_connection.yml)
**Severity:** 🟠 High · **ATT&CK:** T1071.001 (Web Protocols)

## TL;DR
LOLBin (mshta/rundll32/certutil/bitsadmin ฯลฯ) เปิด connection ออกไปยัง IP ภายนอก — เครื่องมือเหล่านี้แทบไม่ต้องต่อเน็ตเอง จึงบ่งชี้ download payload หรือ C2

## Triage (0–15 นาที)
- **binary** ตัวไหนต่อออก, **dest IP** reputation เป็นยังไง
- parent process / บริบทการรัน
- มี data ออกมากผิดปกติไหม

## Contain
1. Block dest IP/domain ที่ firewall
2. Isolate host
3. หา process/ไฟล์ที่เกี่ยวข้อง

## Hunt
```spl
index=sysmon EventCode=3 Initiated=true
  Image IN ("*\\mshta.exe","*\\rundll32.exe","*\\certutil.exe","*\\bitsadmin.exe","*\\wscript.exe")
| search NOT DestinationIp IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
| stats count by host, Image, DestinationIp, _time
```

## หมายเหตุไทย
ใช้ correlate กับ rule LOLBin อื่น (mshta/certutil) เพื่อปะติดปะต่อ chain · ข้อมูลรั่ว → ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-02</sub>
