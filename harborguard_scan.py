#!/usr/bin/env python3
"""
Scan all 9 images via HarbourGuard API, poll until complete,
extract vulnerability metrics, and save to logs/harborguard_results.json.
"""

import json, time, os, requests
from datetime import datetime

BASE = "http://localhost:3000"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(SCRIPT_DIR, "logs", "harborguard_results.json")

IMAGES = [
    {"image": "alpine",                "tag": "3.19",   "safe": "alpine_3.19",          "group": "C"},
    {"image": "nginx",                 "tag": "latest", "safe": "nginx_latest",          "group": "C"},
    {"image": "node",                  "tag": "20",     "safe": "node_20",               "group": "C"},
    {"image": "python",                "tag": "3.12",   "safe": "python_3.12",           "group": "C"},
    {"image": "nginx",                 "tag": "1.19",   "safe": "nginx_1.19",            "group": "B"},
    {"image": "node",                  "tag": "14",     "safe": "node_14",               "group": "B"},
    {"image": "python",                "tag": "3.8",    "safe": "python_3.8",            "group": "B"},
    {"image": "vulnerables/web-dvwa",  "tag": "latest", "safe": "vulnerables_web-dvwa",  "group": "A"},
    {"image": "bkimminich/juice-shop", "tag": "latest", "safe": "bkimminich_juice-shop", "group": "A"},
]

def start_scan(image, tag):
    r = requests.post(f"{BASE}/api/scans/start",
                      json={"image": image, "tag": tag, "source": "registry"},
                      timeout=30)
    r.raise_for_status()
    return r.json()

def poll(request_id, timeout=900):
    deadline = time.time() + timeout
    dots = 0
    while time.time() < deadline:
        r = requests.get(f"{BASE}/api/scans/status/{request_id}", timeout=15)
        if r.status_code == 404:
            time.sleep(5); continue
        r.raise_for_status()
        d = r.json()
        status = d.get("status", "PENDING")
        if status in ("SUCCESS", "FAILED", "PARTIAL"):
            print(f" {status}")
            return d
        if dots % 6 == 0:
            print(".", end="", flush=True)
        dots += 1
        time.sleep(5)
    print(" TIMEOUT")
    return None

def get_scan(scan_id):
    r = requests.get(f"{BASE}/api/scans/{scan_id}", timeout=30)
    return r.json() if r.status_code == 200 else {}

def get_findings(scan_id):
    r = requests.get(f"{BASE}/api/scans/{scan_id}/findings?limit=10000", timeout=60)
    return r.json() if r.status_code == 200 else {}

def main():
    results = []

    for img in IMAGES:
        label = f"{img['image']}:{img['tag']}"
        print(f"\n[{img['group']}] {label}")

        t_start = time.time()
        try:
            resp   = start_scan(img["image"], img["tag"])
            req_id = resp.get("requestId") or resp.get("id")
            print(f"  requestId: {req_id}  polling", end="", flush=True)
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append({**img, "image_tag": label, "error": str(e)})
            continue

        status_data = poll(req_id)
        elapsed = round(time.time() - t_start, 1)

        if not status_data:
            results.append({**img, "image_tag": label, "error": "timeout", "elapsed_s": elapsed})
            continue

        scan_id     = status_data.get("scanId")
        scan_status = status_data.get("status")

        # Full scan record
        scan_detail = get_scan(scan_id) if scan_id else {}
        meta        = scan_detail.get("metadata") or {}

        # Findings
        findings_data = get_findings(scan_id) if scan_id else {}
        vuln_block    = findings_data.get("vulnerabilities", {})
        by_sev        = vuln_block.get("bySeverity", {})
        by_source     = vuln_block.get("bySource", [])     # [{source, count, severities}]
        findings_list = vuln_block.get("findings", [])
        summary       = findings_data.get("summary", {})

        # Overall counts — prefer metadata (most complete), fallback to bySeverity
        total    = meta.get("vulnerabilityCritical", 0) + meta.get("vulnerabilityHigh", 0) + \
                   meta.get("vulnerabilityMedium", 0)   + meta.get("vulnerabilityLow", 0)
        critical = meta.get("vulnerabilityCritical", by_sev.get("CRITICAL", 0))
        high     = meta.get("vulnerabilityHigh",     by_sev.get("HIGH", 0))
        medium   = meta.get("vulnerabilityMedium",   by_sev.get("MEDIUM", 0))
        low      = meta.get("vulnerabilityLow",      by_sev.get("LOW", 0))

        # Fixed count from individual findings
        fixed = sum(1 for f in findings_list
                    if isinstance(f, dict) and f.get("fixedVersion") and
                    str(f["fixedVersion"]).strip())
        fix_pct = round(fixed / total * 100) if total > 0 else 0

        # Risk score
        risk_score = scan_detail.get("riskScore") or meta.get("aggregatedRiskScore")

        # Per-scanner breakdown
        per_scanner = {}
        for src in by_source:
            name = src.get("source", "unknown")
            sevs = src.get("severities", {})
            per_scanner[name] = {
                "total":    src.get("count", 0),
                "critical": sevs.get("CRITICAL", 0),
                "high":     sevs.get("HIGH", 0),
                "medium":   sevs.get("MEDIUM", 0),
                "low":      sevs.get("LOW", 0),
            }

        # Scan duration from timestamps
        started  = scan_detail.get("startedAt")
        finished = scan_detail.get("finishedAt")
        duration_s = None
        if started and finished:
            from datetime import timezone
            fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
            try:
                duration_s = round(
                    (datetime.strptime(finished, fmt) -
                     datetime.strptime(started,  fmt)).total_seconds(), 1)
            except Exception:
                duration_s = elapsed

        print(f"  total={total}  C={critical} H={high} M={medium} L={low}  "
              f"fixed={fixed}({fix_pct}%)  risk={risk_score}  "
              f"scanners={list(per_scanner.keys())}  duration={duration_s}s")

        results.append({
            "image_tag":   label,
            "image":       img["image"],
            "tag":         img["tag"],
            "safe":        img["safe"],
            "group":       img["group"],
            "status":      scan_status,
            "elapsed_s":   elapsed,
            "duration_s":  duration_s,
            "scan_id":     scan_id,
            "request_id":  req_id,
            "total":       total,
            "critical":    critical,
            "high":        high,
            "medium":      medium,
            "low":         low,
            "fixed":       fixed,
            "fix_pct":     fix_pct,
            "risk_score":  risk_score,
            "compliance_score": meta.get("complianceScore"),
            "compliance_grade": summary.get("complianceGrade"),
            "per_scanner": per_scanner,
        })

        time.sleep(2)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n\nDone — {len(results)} images → {OUT}")

if __name__ == "__main__":
    main()
