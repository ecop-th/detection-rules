#!/usr/bin/env python3
"""สร้างตัวเลขใน README อัตโนมัติจาก rule จริง — รันใน CI ทุกครั้งที่ rule เปลี่ยน

แทนที่เนื้อหาระหว่าง marker:
  <!-- STATS:START --> ... <!-- STATS:END -->        (At a glance)
  <!-- COVERAGE:START --> ... <!-- COVERAGE:END -->  (Coverage map)
"""
import glob, re, os, collections
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
README = os.path.join(ROOT, "README.md")
TOTAL_ATTACK_TACTICS = 14

# display name + ตัวอย่าง (curated) ต่อ tactic — แก้ตรงนี้ที่เดียว
TACTICS = {
    "persistence":          ("📌 Persistence",          "Run key, scheduled task, service, Azure AD admin role"),
    "defense-evasion":      ("🥷 Defense Evasion",       "mshta, regsvr32 (Squiblydoo), ล้าง event log, ปิด MFA"),
    "initial-access":       ("🚪 Initial Access",        "RDP เปิดออกเน็ต, SQLi, path traversal, **Log4Shell**"),
    "command-and-control":  ("📡 Command & Control",     "LOLBin ต่อออกเน็ต, C2 ports, DNS แปลก"),
    "execution":            ("▶️ Execution",             "PowerShell encoded, WMIC, **Office macro phishing**"),
    "credential-access":    ("🔑 Credential Access",     "**LSASS dump**, NTDS.dit, Kerberoasting"),
    "exfiltration":         ("📤 Exfiltration",          "SMB ออกนอก, **inbox forwarding (BEC)**, mailbox forward"),
    "collection":           ("📦 Collection",            "M365 mail forwarding rules"),
    "privilege-escalation": ("⬆️ Privilege Escalation",  "service creation, Azure AD role"),
    "lateral-movement":     ("↔️ Lateral Movement",      "**PsExec**, WMIC remote"),
    "impact":               ("💥 Impact",                "**ลบ shadow copy (ransomware)**"),
    "discovery":            ("🔍 Discovery",             "—"),
    "resource-development": ("🧰 Resource Development",   "—"),
    "reconnaissance":       ("🔭 Reconnaissance",        "—"),
}


def collect():
    files = glob.glob(os.path.join(ROOT, "sigma/**/*.yml"), recursive=True) + \
            glob.glob(os.path.join(ROOT, "emerging-threats/**/*.yml"), recursive=True)
    per_tactic = collections.Counter()
    folders = set()
    for f in files:
        d = yaml.safe_load(open(f))
        seen = set()
        for t in d.get("tags", []):
            name = str(t).replace("attack.", "")
            if name in TACTICS and name not in seen:
                per_tactic[name] += 1
                seen.add(name)
        # telemetry folder (sigma subfolder)
        rel = os.path.relpath(f, ROOT)
        if rel.startswith("sigma/"):
            folders.add(rel.split("/")[1])
    return len(files), per_tactic, len(folders) + 1  # +1 = emerging-threats


def render_stats(total, tactics_n):
    return (
        "<!-- STATS:START — auto-generated, อย่าแก้มือ -->\n"
        f"| 🎯 **{total}** | 🗺️ **{tactics_n}** | 🛰️ **7** | ⚡ **48 ชม.** | 🇹🇭 **2 ภาษา** |\n"
        "|:---:|:---:|:---:|:---:|:---:|\n"
        "| detection rules | ATT&CK tactics | telemetry sources | emerging-threat SLA | ไทย + อังกฤษ |\n"
        "<!-- STATS:END -->"
    )


def render_coverage(per_tactic, tactics_n):
    rows = ["<!-- COVERAGE:START — auto-generated, อย่าแก้มือ -->",
            f"ครอบ **{tactics_n} จาก {TOTAL_ATTACK_TACTICS} ATT&CK tactics** — เน้นจุดที่ attacker ในภูมิภาคนี้ใช้จริง:",
            "",
            "| Tactic | Rules | ตัวอย่างที่จับได้ |",
            "|---|:---:|---|"]
    for name, cnt in per_tactic.most_common():
        disp, example = TACTICS[name]
        rows.append(f"| {disp} | {cnt} | {example} |")
    rows.append("<!-- COVERAGE:END -->")
    return "\n".join(rows)


def replace_block(text, start, end, new):
    return re.sub(re.escape(start) + r".*?" + re.escape(end), new, text, flags=re.DOTALL)


def main():
    total, per_tactic, telem = collect()
    tactics_n = len(per_tactic)
    text = open(README, encoding="utf-8").read()
    text = replace_block(text, "<!-- STATS:START", "STATS:END -->", render_stats(total, tactics_n))
    text = replace_block(text, "<!-- COVERAGE:START", "COVERAGE:END -->", render_coverage(per_tactic, tactics_n))
    open(README, "w", encoding="utf-8").write(text)
    print(f"README updated: {total} rules, {tactics_n} tactics")


if __name__ == "__main__":
    main()
