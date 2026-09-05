#!/usr/bin/env python3
"""Compare p_gate verdicts under the rego bundle as it stood BEFORE commit
260f04a ("Add consensus-without-fix review path to p_gate", 2026-06-25)
against the current bundle, on the same 2026-06-21 enriched inputs.

Shows that 17 of 30 images change their Block+Review count and that
php:8.3-apache moves PASS -> REVIEW, i.e. Table 5.7 as printed cannot have
come from a run on 2026-06-21.

Usage:  python3 audit/oldgate.py      (run from the repo root; needs `opa`)
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NEW = ROOT / "policy" / "rego"
CFG = json.loads((ROOT / "policy" / "configs" / "p_gate.json").read_text())
OLD_COMMIT = "260f04a^"


def materialise_old_rego(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    names = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", OLD_COMMIT, "--", "policy/rego/"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    for n in names:
        blob = subprocess.run(["git", "show", f"{OLD_COMMIT}:{n}"],
                              cwd=ROOT, capture_output=True, check=True).stdout
        (dest / Path(n).name).write_bytes(blob)
    return dest


def verdict(rego_dir: Path, safe: str):
    d = json.loads((ROOT / "policy" / "output" / f"{safe}_enriched_rule.json").read_text())
    d["config"] = {k: v for k, v in CFG.items() if not k.startswith("_")}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(d, f)
        path = f.name
    got = {}
    for q in ("block", "review"):
        r = subprocess.run(
            ["opa", "eval", "--input", path, "--data", str(rego_dir),
             "--format", "json", f"data.vuln.gate.{q}"],
            capture_output=True, text=True)
        try:
            got[q] = r.stdout and json.loads(r.stdout)["result"][0]["expressions"][0]["value"] or []
        except Exception:
            got[q] = []
    os.unlink(path)
    tier = "BLOCK" if got["block"] else ("REVIEW" if got["review"] else "PASS")
    return tier, len(got["block"]) + len(got["review"])


def main():
    with tempfile.TemporaryDirectory() as tmp:
        old = materialise_old_rego(Path(tmp) / "rego_old")
        safes = sorted(p.name.replace("_enriched_rule.json", "")
                       for p in (ROOT / "policy" / "output").glob("*_enriched_rule.json"))
        print(f"{'image':28}{'OLD (pre-260f04a)':>22}{'NEW (current)':>20}")
        differ = 0
        totals = [0, 0]
        for s in safes:
            o, n = verdict(old, s), verdict(NEW, s)
            totals[0] += o[1]
            totals[1] += n[1]
            if o != n:
                differ += 1
            print(f"{s:28}{str(o):>22}{str(n):>20}"
                  + ("   <== DIFFERS" if o != n else ""))
        print(f"\nimages differing: {differ}/30")
        print(f"Block+Review total   OLD={totals[0]}   NEW={totals[1]} "
              f"(thesis Table 5.7 reports {totals[1]})")


if __name__ == "__main__":
    main()
