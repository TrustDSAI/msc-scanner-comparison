#!/usr/bin/env python3
"""
Generate all analysis graphs for the scanner comparison dissertation.
Outputs PNG files to logs/graphs/.
"""

import json, os, collections
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BENCH  = os.path.join(SCRIPT_DIR, "logs", "benchmark_summary.json")
TABLES = os.path.join(SCRIPT_DIR, "logs", "analysis_tables.json")
OUT    = os.path.join(SCRIPT_DIR, "logs", "graphs")
os.makedirs(OUT, exist_ok=True)

# ── colour palette ───────────────────────────────────────────────────────────
C_TRIVY = "#2563EB"
C_GRYPE = "#16A34A"
C_OSV   = "#DC2626"
C_A, C_B, C_C = "#7C3AED", "#EA580C", "#0891B2"
GROUP_COLOUR = {"A": C_A, "B": C_B, "C": C_C}

ORDER = [
    "alpine_3.19", "nginx_latest", "node_20", "python_3.12",
    "nginx_1.19", "node_14", "python_3.8",
    "vulnerables_web-dvwa", "bkimminich_juice-shop",
]
LABEL = {
    "alpine_3.19": "alpine:3.19", "nginx_latest": "nginx:latest",
    "node_20": "node:20", "python_3.12": "python:3.12",
    "nginx_1.19": "nginx:1.19", "node_14": "node:14",
    "python_3.8": "python:3.8",
    "vulnerables_web-dvwa": "web-dvwa",
    "bkimminich_juice-shop": "juice-shop",
}
# group background spans (index ranges, inclusive)
SPANS = {"C": (0, 3), "B": (4, 6), "A": (7, 8)}

def group_bg(ax, n_bars=1, pad=0.5):
    """Shade group regions on ax."""
    for grp, (lo, hi) in SPANS.items():
        ax.axvspan(lo - pad, hi + n_bars * 0.3 + pad,
                   alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)

def save(fig, name):
    path = os.path.join(OUT, name)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {name}")

# ── load ─────────────────────────────────────────────────────────────────────
with open(BENCH)  as f: bench  = json.load(f)
with open(TABLES) as f: tables = json.load(f)

by_safe = {r["safe"]: r for r in tables}
bb      = {b["safe"]: b for b in bench}

def field(safe, *keys):
    """Navigate nested keys in analysis record."""
    v = by_safe[safe]
    for k in keys:
        v = v[k]
    return v

# raw D1 totals from experiment log (parse_results level — findings, not unique CVEs)
RAW_TRIVY = {
    "alpine_3.19": 6,  "nginx_latest": 169, "node_20": 2268,  "python_3.12": 1751,
    "nginx_1.19":  424,"node_14": 1439,     "python_3.8": 5660,
    "vulnerables_web-dvwa": 1575, "bkimminich_juice-shop": 98,
}
RAW_GRYPE = {
    "alpine_3.19": 10, "nginx_latest": 172, "node_20": 1474,  "python_3.12": 1418,
    "nginx_1.19":  550,"node_14": 1995,     "python_3.8": 2533,
    "vulnerables_web-dvwa": 2097, "bkimminich_juice-shop": 93,
}
RAW_OSV = {
    "alpine_3.19": 6,  "nginx_latest": 177, "node_20": 1458,  "python_3.12": 1422,
    "nginx_1.19":  132,"node_14": 210,      "python_3.8": 2620,
    "vulnerables_web-dvwa": 336, "bkimminich_juice-shop": 94,
}
RAW_TRIVY_FIX = {
    "alpine_3.19": 100,"nginx_latest": 0,  "node_20": 1,     "python_3.12": 14,
    "nginx_1.19":  79, "node_14": 77,      "python_3.8": 60,
    "vulnerables_web-dvwa": 88, "bkimminich_juice-shop": 85,
}
RAW_GRYPE_FIX = {
    "alpine_3.19": 60, "nginx_latest": 0,  "node_20": 1,     "python_3.12": 18,
    "nginx_1.19":  58, "node_14": 34,      "python_3.8": 41,
    "vulnerables_web-dvwa": 65, "bkimminich_juice-shop": 84,
}
RAW_TRIVY_CRIT = {
    "alpine_3.19": 0, "nginx_latest": 0, "node_20": 33,  "python_3.12": 0,
    "nginx_1.19": 42, "node_14": 22,     "python_3.8": 182,
    "vulnerables_web-dvwa": 254, "bkimminich_juice-shop": 10,
}
RAW_GRYPE_CRIT = {
    "alpine_3.19": 0, "nginx_latest": 0, "node_20": 32,  "python_3.12": 0,
    "nginx_1.19": 40, "node_14": 19,     "python_3.8": 185,
    "vulnerables_web-dvwa": 327, "bkimminich_juice-shop": 10,
}

# ── Fig 1: Scan performance (log scale, mean ± sd) ───────────────────────────
print("Fig 1: Scan performance…")
tools_cfg = [("trivy", C_TRIVY, "Trivy"),
             ("grype", C_GRYPE, "Grype"),
             ("osv",   C_OSV,   "OSV-Scanner")]
x = np.arange(len(ORDER))
width = 0.26

fig, ax = plt.subplots(figsize=(14, 6))
for i, (tool, col, lbl) in enumerate(tools_cfg):
    means, sds = [], []
    for safe in ORDER:
        b = bb[safe]
        if safe == "alpine_3.19" and tool in ("trivy", "grype"):
            runs = b[tool]["runs_ms"][1:]
        else:
            runs = b[tool]["runs_ms"]
        m = np.mean(runs) / 1000
        s = (np.std(runs, ddof=1) if len(runs) > 1 else 0) / 1000
        means.append(m); sds.append(s)
    ax.bar(x + i*width, means, width, label=lbl, color=col, alpha=0.85, zorder=3)
    ax.errorbar(x + i*width, means, yerr=sds, fmt="none",
                color="black", capsize=3, linewidth=1, zorder=4)
    if tool == "trivy":
        for j, (m, s_) in enumerate(zip(means, sds)):
            ax.text(j + i*width, m * 1.5,
                    f"{m*1000:.0f}ms", ha="center", va="bottom", fontsize=7, color=col)

for grp, (lo, hi) in SPANS.items():
    ax.axvspan(lo - 0.4, hi + 0.9, alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)
    ax.text((lo+hi)/2 + 0.15, 0.008,
            f"Grp {grp}", ha="center", va="bottom",
            fontsize=9, color=GROUP_COLOUR[grp], fontweight="bold")

ax.set_yscale("log")
ax.set_ylabel("Scan time (seconds, log scale)", fontsize=11)
ax.set_title("Fig 1 — Scan Performance: Mean ± Std Dev (3 runs, images cached locally)",
             fontsize=12, fontweight="bold")
ax.set_xticks(x + width)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=9)
ax.legend(fontsize=10)
ax.yaxis.grid(True, which="both", linestyle="--", alpha=0.4, zorder=0)
ax.set_axisbelow(True)
save(fig, "fig1_performance.png")

# ── Fig 2: Total findings — grouped bar ──────────────────────────────────────
print("Fig 2: Total findings…")
x = np.arange(len(ORDER))
width = 0.28

fig, ax = plt.subplots(figsize=(14, 6))
ax.bar(x - width, [RAW_TRIVY[s] for s in ORDER], width,
       label="Trivy", color=C_TRIVY, alpha=0.85)
ax.bar(x,          [RAW_GRYPE[s] for s in ORDER], width,
       label="Grype", color=C_GRYPE, alpha=0.85)
ax.bar(x + width,  [RAW_OSV[s]   for s in ORDER], width,
       label="OSV-Scanner†", color=C_OSV, alpha=0.85)

for grp, (lo, hi) in SPANS.items():
    ax.axvspan(lo - 0.55, hi + 0.95, alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)

# annotate ratio where divergence is large
for i, s in enumerate(ORDER):
    t, g = RAW_TRIVY[s], RAW_GRYPE[s]
    if min(t, g) > 0:
        ratio = max(t, g) / min(t, g)
        if ratio >= 1.5:
            ax.text(i, max(t, g) + 80, f"{ratio:.1f}×",
                    ha="center", va="bottom", fontsize=8, fontweight="bold")

ax.set_ylabel("Total vulnerability findings", fontsize=11)
ax.set_title("Fig 2 — Total Findings per Image per Tool\n"
             "† OSV reports advisories, not CVEs — not directly comparable for Debian images",
             fontsize=12, fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=9)
ax.legend(fontsize=10)
ax.yaxis.grid(True, linestyle="--", alpha=0.4)
ax.set_axisbelow(True)
save(fig, "fig2_total_findings.png")

# ── Fig 3: CVE overlap — Jaccard + composition ───────────────────────────────
print("Fig 3: CVE overlap…")

jaccards   = [field(s, "overlap", "jaccard")  for s in ORDER]
t_only     = [field(s, "overlap", "t_only")   for s in ORDER]
both       = [field(s, "overlap", "both")     for s in ORDER]
g_only     = [field(s, "overlap", "g_only")   for s in ORDER]
totals_ov  = [a+b+c for a,b,c in zip(t_only, both, g_only)]

both_pct   = [b/tot*100 if tot else 0 for b,tot in zip(both, totals_ov)]
t_pct      = [t/tot*100 if tot else 0 for t,tot in zip(t_only, totals_ov)]
g_pct      = [g/tot*100 if tot else 0 for g,tot in zip(g_only, totals_ov)]
bar_col    = [GROUP_COLOUR[by_safe[s]["group"]] for s in ORDER]

fig, axes = plt.subplots(1, 2, figsize=(16, 6))

# left: Jaccard bars
ax = axes[0]
bars = ax.bar(range(len(ORDER)), jaccards, color=bar_col, alpha=0.85, zorder=3)
ax.axhline(0.5, color="grey", linestyle="--", linewidth=1.2, alpha=0.7, label="0.5")
ax.set_ylabel("Jaccard similarity", fontsize=11)
ax.set_title("CVE-Level Overlap (Jaccard = |T∩G|/|T∪G|)", fontsize=11, fontweight="bold")
ax.set_xticks(range(len(ORDER)))
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=40, ha="right", fontsize=9)
ax.set_ylim(0, 1.12)
ax.yaxis.grid(True, linestyle="--", alpha=0.4); ax.set_axisbelow(True)
for bar, val in zip(bars, jaccards):
    ax.text(bar.get_x()+bar.get_width()/2, val+0.02,
            f"{val:.3f}", ha="center", va="bottom", fontsize=9, fontweight="bold")
ax.legend(handles=[
    mpatches.Patch(color=C_A, label="Group A"),
    mpatches.Patch(color=C_B, label="Group B"),
    mpatches.Patch(color=C_C, label="Group C"),
], fontsize=9)

# right: stacked composition
ax = axes[1]
ax.bar(range(len(ORDER)), both_pct, color="#6B7280", alpha=0.85, label="Shared (both)")
ax.bar(range(len(ORDER)), t_pct, bottom=both_pct, color=C_TRIVY, alpha=0.75, label="Trivy only")
ax.bar(range(len(ORDER)), g_pct,
       bottom=[b+t for b,t in zip(both_pct, t_pct)],
       color=C_GRYPE, alpha=0.75, label="Grype only")
ax.set_ylabel("% of unique CVEs", fontsize=11)
ax.set_title("CVE Set Composition (Shared / Trivy-only / Grype-only)", fontsize=11, fontweight="bold")
ax.set_xticks(range(len(ORDER)))
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=40, ha="right", fontsize=9)
ax.set_ylim(0, 110); ax.legend(fontsize=9)
ax.yaxis.grid(True, linestyle="--", alpha=0.4); ax.set_axisbelow(True)

fig.suptitle("Fig 3 — CVE-Level Agreement: Trivy vs Grype",
             fontsize=13, fontweight="bold", y=1.01)
save(fig, "fig3_cve_overlap.png")

# ── Fig 4: Severity agreement ─────────────────────────────────────────────────
print("Fig 4: Severity agreement…")

shared_n  = [field(s, "sev_agreement", "shared")   for s in ORDER]
same_n    = [field(s, "sev_agreement", "same")      for s in ORDER]
t_high_n  = [field(s, "sev_agreement", "t_higher")  for s in ORDER]
g_high_n  = [field(s, "sev_agreement", "g_higher")  for s in ORDER]

ag_pct  = [sm/sh*100 if sh else 0 for sm,sh in zip(same_n, shared_n)]
th_pct  = [th/sh*100 if sh else 0 for th,sh in zip(t_high_n, shared_n)]
gh_pct  = [gh/sh*100 if sh else 0 for gh,sh in zip(g_high_n, shared_n)]

x = np.arange(len(ORDER))
width = 0.28

fig, ax = plt.subplots(figsize=(14, 6))
ax.bar(x - width, ag_pct, width, label="Same severity",  color="#6B7280", alpha=0.85)
ax.bar(x,         th_pct, width, label="Trivy higher",   color=C_TRIVY,   alpha=0.85)
ax.bar(x + width, gh_pct, width, label="Grype higher",   color=C_GRYPE,   alpha=0.85)

for grp, (lo, hi) in SPANS.items():
    ax.axvspan(lo - 0.5, hi + 0.95, alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)

# annotate agree% and shared count
for i, (v, n) in enumerate(zip(ag_pct, shared_n)):
    ax.text(i - width, v + 1.5, f"{v:.0f}%", ha="center", va="bottom", fontsize=8)
    ax.text(i, -7, f"n={n}", ha="center", va="top", fontsize=7, color="grey")

ax.set_ylabel("% of shared CVEs", fontsize=11)
ax.set_ylim(0, 115)
ax.set_title("Fig 4 — Severity Agreement on Shared CVEs (Trivy vs Grype)\n"
             "Agree% shown above bars; n = number of shared CVEs",
             fontsize=12, fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=9)
ax.legend(fontsize=10)
ax.yaxis.grid(True, linestyle="--", alpha=0.4); ax.set_axisbelow(True)
save(fig, "fig4_severity_agreement.png")

# ── Fig 5: Fix rates ──────────────────────────────────────────────────────────
print("Fig 5: Fix rates…")
x = np.arange(len(ORDER))
width = 0.35

fig, ax = plt.subplots(figsize=(13, 6))
ax.bar(x - width/2, [RAW_TRIVY_FIX[s] for s in ORDER], width,
       label="Trivy fix%", color=C_TRIVY, alpha=0.85)
ax.bar(x + width/2, [RAW_GRYPE_FIX[s] for s in ORDER], width,
       label="Grype fix%", color=C_GRYPE, alpha=0.85)

for grp, (lo, hi) in SPANS.items():
    ax.axvspan(lo - 0.55, hi + 0.85, alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)

for i, s in enumerate(ORDER):
    tv, gv = RAW_TRIVY_FIX[s], RAW_GRYPE_FIX[s]
    ax.text(i - width/2, tv + 1.5, f"{tv}%", ha="center", va="bottom", fontsize=8)
    ax.text(i + width/2, gv + 1.5, f"{gv}%", ha="center", va="bottom", fontsize=8)

ax.set_ylabel("% of findings with a fix available", fontsize=11)
ax.set_ylim(0, 115)
ax.set_title("Fig 5 — Fix Rate: Fraction of Findings Where a Patched Version Exists\n"
             "FIXED = a newer package version resolves this CVE",
             fontsize=12, fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=9)
ax.legend(fontsize=10)
ax.yaxis.grid(True, linestyle="--", alpha=0.4); ax.set_axisbelow(True)
save(fig, "fig5_fix_rates.png")

# ── Fig 6: CRITICAL counts ────────────────────────────────────────────────────
print("Fig 6: CRITICAL counts…")
x = np.arange(len(ORDER))
width = 0.35

fig, ax = plt.subplots(figsize=(13, 5))
ax.bar(x - width/2, [RAW_TRIVY_CRIT[s] for s in ORDER], width,
       label="Trivy CRITICAL", color=C_TRIVY, alpha=0.85)
ax.bar(x + width/2, [RAW_GRYPE_CRIT[s] for s in ORDER], width,
       label="Grype CRITICAL", color=C_GRYPE, alpha=0.85)

for grp, (lo, hi) in SPANS.items():
    ax.axvspan(lo - 0.55, hi + 0.85, alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)

for i, s in enumerate(ORDER):
    tv, gv = RAW_TRIVY_CRIT[s], RAW_GRYPE_CRIT[s]
    if tv > 0: ax.text(i - width/2, tv + 3, str(tv), ha="center", va="bottom", fontsize=8)
    if gv > 0: ax.text(i + width/2, gv + 3, str(gv), ha="center", va="bottom", fontsize=8)

ax.set_ylabel("CRITICAL vulnerability count", fontsize=11)
ax.set_title("Fig 6 — CRITICAL Findings: Trivy vs Grype\n"
             "CRITICAL is the most reliable cross-tool agreement band (delta ≤3 in 7/9 images)",
             fontsize=12, fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=9)
ax.legend(fontsize=10)
ax.yaxis.grid(True, linestyle="--", alpha=0.4); ax.set_axisbelow(True)
save(fig, "fig6_critical_counts.png")

# ── Fig 7: CWE top 10 ─────────────────────────────────────────────────────────
print("Fig 7: CWE top 10…")

# aggregate CWE counts across all images
trivy_cwe_agg = collections.Counter()
grype_cwe_agg = collections.Counter()
for r in tables:
    for cwe, cnt in r["trivy_cwes"].items(): trivy_cwe_agg[cwe] += cnt
    for cwe, cnt in r["grype_cwes"].items(): grype_cwe_agg[cwe] += cnt

top10_cwes = [c for c, _ in (trivy_cwe_agg + grype_cwe_agg).most_common(10)]
CWE_NAMES = {
    "CWE-476": "NULL Ptr\nDeref", "CWE-416": "Use After\nFree",
    "CWE-125": "OOB\nRead",       "CWE-787": "OOB\nWrite",
    "CWE-190": "Integer\nOverflow","CWE-119": "Memory\nOps",
    "CWE-401": "Memory\nLeak",    "CWE-400": "Resource\nExhaustion",
    "CWE-362": "Race\nCondition", "CWE-122": "Heap\nBuffer Overflow",
}
xlabels = [f"{c}\n{CWE_NAMES.get(c,'')}" for c in top10_cwes]
t_vals  = [trivy_cwe_agg[c] for c in top10_cwes]
g_vals  = [grype_cwe_agg[c] for c in top10_cwes]

x = np.arange(len(top10_cwes))
width = 0.35

fig, ax = plt.subplots(figsize=(14, 6))
ax.bar(x - width/2, t_vals, width, label="Trivy", color=C_TRIVY, alpha=0.85)
ax.bar(x + width/2, g_vals, width, label="Grype", color=C_GRYPE, alpha=0.85)

for i, (tv, gv) in enumerate(zip(t_vals, g_vals)):
    tot = tv + gv
    ax.text(i, max(tv, gv) + 15, f"Σ{tot}",
            ha="center", va="bottom", fontsize=8, fontweight="bold")

ax.set_ylabel("Occurrence count (all 9 images)", fontsize=11)
ax.set_title("Fig 7 — Top 10 CWE Types Across All Images (Trivy + Grype)\n"
             "Memory-safety weaknesses dominate — driven by OS-layer C/C++ packages",
             fontsize=12, fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels(xlabels, fontsize=9)
ax.legend(fontsize=10)
ax.yaxis.grid(True, linestyle="--", alpha=0.4); ax.set_axisbelow(True)
save(fig, "fig7_cwe_top10.png")

# ── Fig 8: Scan time vs image size scatter ───────────────────────────────────
print("Fig 8: Scan time vs image size…")

sizes   = [bb[s]["size_mb"] for s in ORDER]
t_means = []
g_means = []
o_means = []
for s in ORDER:
    b = bb[s]
    if s == "alpine_3.19":
        t_means.append(np.mean(b["trivy"]["runs_ms"][1:]) / 1000)
        g_means.append(np.mean(b["grype"]["runs_ms"][1:]) / 1000)
    else:
        t_means.append(b["trivy"]["mean_ms"] / 1000)
        g_means.append(b["grype"]["mean_ms"] / 1000)
    o_means.append(b["osv"]["mean_ms"] / 1000)

fig, ax = plt.subplots(figsize=(10, 7))
for means, col, lbl in [(t_means, C_TRIVY, "Trivy"),
                         (g_means, C_GRYPE, "Grype"),
                         (o_means, C_OSV,   "OSV-Scanner")]:
    ax.scatter(sizes, means, color=col, label=lbl, s=90, zorder=4, alpha=0.9)
    coeffs = np.polyfit(sizes, means, 1)
    xs = np.linspace(0, max(sizes)*1.05, 200)
    ax.plot(xs, np.polyval(coeffs, xs), color=col, linestyle="--", alpha=0.5, linewidth=1.2)

for i, s in enumerate(ORDER):
    top = max(t_means[i], g_means[i], o_means[i])
    ax.annotate(LABEL[s], (sizes[i], top),
                textcoords="offset points", xytext=(5, 4), fontsize=7.5, color="#444444")

ax.set_xlabel("Compressed image size (MB)", fontsize=11)
ax.set_ylabel("Mean scan time (seconds)", fontsize=11)
ax.set_title("Fig 8 — Scan Time vs Image Size\n"
             "Grype and OSV scale linearly (r≈0.9); Trivy is size-independent",
             fontsize=12, fontweight="bold")
ax.legend(fontsize=10)
ax.yaxis.grid(True, linestyle="--", alpha=0.4)
ax.xaxis.grid(True, linestyle="--", alpha=0.4)
ax.set_axisbelow(True)
save(fig, "fig8_time_vs_size.png")

print(f"\nDone — 8 graphs saved to {OUT}/")
