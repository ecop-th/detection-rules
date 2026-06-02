#!/usr/bin/env python3
"""Enforce ECOP rule metadata standards beyond plain Sigma schema.

ทุก rule ต้องมี: author (ไม่ใช่ค่าว่าง/Unknown), attack tag, falsepositives, level.
รันใน CI — exit code != 0 ถ้ามี rule ไม่ผ่าน
"""
import sys
import glob
import yaml

REQUIRED_LEVELS = {"informational", "low", "medium", "high", "critical"}
RULE_GLOBS = ["sigma/**/*.yml", "emerging-threats/**/*.yml"]


def lint(path: str) -> list[str]:
    errors: list[str] = []
    with open(path, encoding="utf-8") as fh:
        try:
            doc = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            return [f"YAML parse error: {exc}"]

    if not isinstance(doc, dict):
        return ["ไฟล์ไม่ใช่ Sigma rule ที่ถูกต้อง (top-level ต้องเป็น mapping)"]

    author = str(doc.get("author", "")).strip()
    if not author or author.lower() == "unknown":
        errors.append("ต้องระบุ author จริง (นี่คือ portfolio ของคุณ)")

    tags = doc.get("tags") or []
    if not any(str(t).startswith("attack.t") for t in tags):
        errors.append("ต้องมี MITRE ATT&CK technique tag อย่างน้อย 1 (เช่น attack.t1003.001)")

    fps = doc.get("falsepositives")
    if not fps or (isinstance(fps, list) and all(str(x).strip().lower() in {"", "unknown"} for x in fps)):
        errors.append("ต้องเขียน falsepositives จากของจริง ห้ามเป็น 'Unknown'")

    level = str(doc.get("level", "")).strip().lower()
    if level not in REQUIRED_LEVELS:
        errors.append(f"level ต้องเป็นหนึ่งใน {sorted(REQUIRED_LEVELS)}")

    return errors


def main() -> int:
    files = sorted({f for pat in RULE_GLOBS for f in glob.glob(pat, recursive=True)})
    if not files:
        print("ไม่พบ rule ให้ตรวจ")
        return 0

    failed = False
    for path in files:
        problems = lint(path)
        if problems:
            failed = True
            print(f"\n✗ {path}")
            for p in problems:
                print(f"    - {p}")
        else:
            print(f"✓ {path}")

    if failed:
        print("\nมี rule ไม่ผ่านมาตรฐาน metadata ของ ECOP — ดูรายละเอียดด้านบน")
        return 1
    print(f"\nผ่านทั้งหมด {len(files)} rules ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
