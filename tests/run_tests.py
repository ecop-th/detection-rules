#!/usr/bin/env python3
"""ECOP rule test runner — พิสูจน์ว่าทุก rule จับ log ได้จริง

จับคู่อัตโนมัติ: tests/positive/<rule_basename>.json  ↔  sigma/**/<rule_basename>.yml
  - positive sample ต้อง MATCH
  - negative sample ต้อง NO MATCH
รันใน CI ทุก push/PR. exit != 0 ถ้ามีเทสต์ไม่ผ่าน
"""
import sys, json, glob, os
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_rule(basename):
    for pat in ("sigma/**/%s.yml", "emerging-threats/**/%s.yml"):
        hits = glob.glob(os.path.join(ROOT, pat % basename), recursive=True)
        if hits:
            return hits[0]
    return None


def field_match(key, expected, event):
    parts = key.split("|")
    field, mods = parts[0], parts[1:]
    if field not in event:
        return False
    actual = str(event[field]).lower()
    vals = expected if isinstance(expected, list) else [expected]
    vals = [str(v).lower() for v in vals]

    def one(v):
        if "endswith" in mods:   return actual.endswith(v)
        if "startswith" in mods: return actual.startswith(v)
        if "contains" in mods:   return v in actual
        return actual == v

    return all(one(v) for v in vals) if "all" in mods else any(one(v) for v in vals)


def sel_match(sel, event):
    if isinstance(sel, list):
        return any(sel_match(s, event) for s in sel)
    return all(field_match(k, v, event) for k, v in sel.items())


def eval_rule(detection, event):
    names = {k: sel_match(v, event) for k, v in detection.items() if k != "condition"}
    expr = detection["condition"]
    # longest names first to avoid partial replacement
    for n in sorted(names, key=len, reverse=True):
        expr = expr.replace(n, str(names[n]))
    return bool(eval(expr, {"__builtins__": {}}, {}))


def run():
    passed = failed = 0
    for expect, folder in ((True, "positive"), (False, "negative")):
        for sample in sorted(glob.glob(os.path.join(ROOT, "tests", folder, "*.json"))):
            base = os.path.basename(sample)[:-5]
            rule_path = find_rule(base)
            if not rule_path:
                print(f"  [SKIP] {base} — ไม่พบ rule ที่ตรงกัน")
                continue
            rule = yaml.safe_load(open(rule_path))
            event = json.load(open(sample))
            hit = eval_rule(rule["detection"], event)
            ok = hit == expect
            mark = "PASS ✅" if ok else "FAIL ❌"
            got = "MATCH" if hit else "NO MATCH"
            want = "MATCH" if expect else "NO MATCH"
            print(f"  [{mark}] {folder:8s} {base:48s} got={got:9s} want={want}")
            passed += ok
            failed += not ok
    print(f"\n  รวม: {passed} ผ่าน, {failed} ไม่ผ่าน")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    print("ECOP Detection Rules — behaviour tests\n")
    sys.exit(run())
