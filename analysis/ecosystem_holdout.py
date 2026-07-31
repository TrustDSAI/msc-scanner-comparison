#!/usr/bin/env python3
"""Ecosystem-split generalisation test: design set vs held-out extension.

Tests whether an image's package ecosystem predicts cross-scanner agreement,
by fitting the split on the nine design images and testing it on the 21
extension images.

CLASSIFICATION RULE (the thing that was previously undocumented):

    An image is OS-only if neither scanner reports a finding against a
    language-ecosystem package. Any npm, PyPI, gem, Go, Maven or NuGet
    finding makes it mixed.

    Trivy: a Results block with Class == "lang-pkgs".
    Grype: a match whose artifact.type is not a distro package type
           (deb, rpm, apk, and the empty string for unknown).

That rule is not arbitrary: it reproduces the design set's published 4/5
split exactly (alpine:3.19, both nginx, web-dvwa OS-only; juice-shop,
both node, both python mixed), and with it the published training
statistics fall out to three decimals. The script asserts that before
reporting anything about the held-out set, so a change to the rule or to
the underlying data fails loudly instead of quietly moving the numbers.

Jaccard uses the same canonical-identifier rule as analysis.py: one
identifier per Grype match, its own CVE if it has one, else its first
CVE alias, else the raw GHSA.

Usage:
    python3 analysis/ecosystem_holdout.py            # print the numbers
    python3 analysis/ecosystem_holdout.py --figure   # also write the figure
"""

import argparse
import glob
import json
import os
import statistics
import sys

from scipy.stats import mannwhitneyu

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
FIGDIR = os.path.join(ROOT, "figures")

DESIGN = {
    "alpine_3.19", "nginx_1.29.7", "node_20", "python_3.12",
    "nginx_1.19", "node_14", "python_3.8",
    "vulnerables_web-dvwa", "bkimminich_juice-shop",
}

DISTRO_PKG_TYPES = {"deb", "rpm", "apk", ""}

# Published design-set values these must reproduce before the held-out
# result is reported (Section 5.1.2).
EXPECTED_TRAINING = {
    "os_mean": 0.71, "mixed_mean": 0.41,
    "n_os": 4, "n_mixed": 5,
    "u": 16.0, "p": 0.095,
}

LABEL = {
    "alpine_3.19": "alpine:3.19", "nginx_1.29.7": "nginx:1.29.7",
    "node_20": "node:20", "python_3.12": "python:3.12",
    "nginx_1.19": "nginx:1.19", "node_14": "node:14",
    "python_3.8": "python:3.8", "vulnerables_web-dvwa": "web-dvwa",
    "bkimminich_juice-shop": "juice-shop",
}


def canonical_grype_ids(gj):
    """One identifier per match, matching analysis.py."""
    ids = set()
    lang = False
    for m in gj.get("matches", []):
        vid = (m.get("vulnerability") or {}).get("id", "")
        if not vid:
            continue
        related = [r.get("id", "") for r in (m.get("relatedVulnerabilities") or [])
                   if r.get("id", "").startswith("CVE-")]
        ids.add(vid if vid.startswith("CVE-") else (related[0] if related else vid))
        if (m.get("artifact") or {}).get("type", "") not in DISTRO_PKG_TYPES:
            lang = True
    return ids, lang


def measure(safe):
    """Return (jaccard, ecosystem) for one image."""
    with open(os.path.join(RAW, "trivy", f"{safe}_trivy.json")) as f:
        tj = json.load(f)
    t_ids, lang = set(), False
    for r in tj.get("Results", []):
        vulns = r.get("Vulnerabilities") or []
        if r.get("Class") == "lang-pkgs" and vulns:
            lang = True
        for v in vulns:
            if v.get("VulnerabilityID"):
                t_ids.add(v["VulnerabilityID"])

    with open(os.path.join(RAW, "grype", f"{safe}_grype.json")) as f:
        gj = json.load(f)
    g_ids, g_lang = canonical_grype_ids(gj)

    union = t_ids | g_ids
    jaccard = len(t_ids & g_ids) / len(union) if union else 0.0
    return jaccard, ("mixed" if (lang or g_lang) else "os")


def collect():
    rows = []
    for path in sorted(glob.glob(os.path.join(RAW, "trivy", "*_trivy.json"))):
        safe = os.path.basename(path).replace("_trivy.json", "")
        if not os.path.exists(os.path.join(RAW, "grype", f"{safe}_grype.json")):
            continue
        jaccard, eco = measure(safe)
        rows.append({"safe": safe, "jaccard": jaccard, "eco": eco,
                     "design": safe in DESIGN})
    return rows


def stats_for(rows):
    os_vals = [r["jaccard"] for r in rows if r["eco"] == "os"]
    mx_vals = [r["jaccard"] for r in rows if r["eco"] == "mixed"]
    out = {
        "os_mean": round(statistics.mean(os_vals), 3) if os_vals else None,
        "mixed_mean": round(statistics.mean(mx_vals), 3) if mx_vals else None,
        "n_os": len(os_vals), "n_mixed": len(mx_vals),
    }
    if len(os_vals) > 1 and len(mx_vals) > 1:
        # one-sided, matching the thesis's a priori hypothesis OS-only > mixed
        u, p = mannwhitneyu(os_vals, mx_vals, alternative="greater")
        out["u"], out["p"] = float(u), round(float(p), 3)
    return out


def self_check(training):
    """Refuse to report the held-out result unless the published training
    statistics are reproduced first."""
    bad = []
    for k, expected in EXPECTED_TRAINING.items():
        got = training.get(k)
        if got is None or abs(got - expected) > 0.006:
            bad.append(f"    {k}: expected {expected}, got {got}")
    if bad:
        print("SELF-CHECK FAILED: does not reproduce the published design-set "
              "statistics.\n" + "\n".join(bad), file=sys.stderr)
        sys.exit(1)
    print("Self-check passed: reproduces the published design-set statistics "
          "(Section 5.1.2).\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--figure", action="store_true", help="write the figure")
    args = ap.parse_args()

    rows = collect()
    training = stats_for([r for r in rows if r["design"]])
    heldout = stats_for([r for r in rows if not r["design"]])

    self_check(training)

    for name, st, n in (("TRAINING (9 design images)", training, 9),
                        ("HELD-OUT (21 extension images)", heldout, 21)):
        print(f"{name}")
        print(f"  OS-only mean : {st['os_mean']}  (n={st['n_os']})")
        print(f"  mixed mean   : {st['mixed_mean']}  (n={st['n_mixed']})")
        if "u" in st:
            print(f"  Mann-Whitney : U={st['u']:.0f}, one-sided p={st['p']}")
        print()

    combined = stats_for(rows)
    print("ALL 30 IMAGES")
    print(f"  OS-only mean : {combined['os_mean']}  (n={combined['n_os']})")
    print(f"  mixed mean   : {combined['mixed_mean']}  (n={combined['n_mixed']})")
    if "u" in combined:
        print(f"  Mann-Whitney : U={combined['u']:.0f}, one-sided p={combined['p']}")

    if args.figure:
        write_figure(rows, training, heldout)


def write_figure(rows, training, heldout):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Palatino", "URW Palladio L", "STIXGeneral", "DejaVu Serif"],
        "axes.edgecolor": "#4A4A4A", "axes.linewidth": 0.8,
        "axes.spines.top": False, "axes.spines.right": False,
        "font.size": 10, "axes.labelsize": 10,
        "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.fontsize": 9,
    })
    C_OS, C_MIX = "#0072B2", "#B03A2E"

    fig, axes = plt.subplots(1, 2, figsize=(6.5, 4.2),
                             gridspec_kw={"width_ratios": [1, 1.6]})
    for ax, subset, st, title in (
        (axes[0], [r for r in rows if r["design"]], training, "Design set (n=9)"),
        (axes[1], [r for r in rows if not r["design"]], heldout, "Held-out extension (n=21)"),
    ):
        sub = sorted(subset, key=lambda r: r["jaccard"])
        names = [LABEL.get(r["safe"], r["safe"].replace("_", ":")) for r in sub]
        ax.barh(range(len(sub)), [r["jaccard"] for r in sub],
                color=[C_OS if r["eco"] == "os" else C_MIX for r in sub],
                alpha=0.9, height=0.7)
        ax.axvline(st["os_mean"], color=C_OS, linestyle="--", linewidth=1.2)
        ax.axvline(st["mixed_mean"], color=C_MIX, linestyle="--", linewidth=1.2)
        ax.set_yticks(range(len(sub)))
        ax.set_yticklabels(names, fontsize=8)
        ax.set_xlim(0, 1.0)
        ax.set_xlabel("CVE-level Jaccard similarity", fontsize=9)
        ax.set_title(title, fontsize=10, fontweight="bold", loc="left")
        ax.xaxis.grid(True, linestyle="-", alpha=0.18)
        ax.set_axisbelow(True)

    import matplotlib.patches as mpatches
    fig.legend(handles=[mpatches.Patch(color=C_OS, label="Operating-system packages only"),
                        mpatches.Patch(color=C_MIX, label="Mixed ecosystem")],
               loc="lower center", ncol=2, frameon=False, bbox_to_anchor=(0.5, -0.02))
    fig.tight_layout(rect=[0, 0.06, 1, 1])
    out = os.path.join(FIGDIR, "fig9_ecosystem_holdout.pdf")
    fig.savefig(out, bbox_inches="tight")
    fig.savefig(out.replace(".pdf", ".png"), dpi=150, bbox_inches="tight")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
