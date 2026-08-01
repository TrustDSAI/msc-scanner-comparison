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

ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH  = os.path.join(ROOT, "data", "derived", "benchmark_summary.json")
TABLES = os.path.join(ROOT, "data", "derived", "analysis_tables.json")
OUT    = os.path.join(ROOT, "figures")
os.makedirs(OUT, exist_ok=True)

# ── typography & chart style (print-oriented, matches thesis body serif) ────
plt.rcParams.update({
    "font.family":       "serif",
    "font.serif":        ["Palatino", "Palatino Linotype", "URW Palladio L", "STIXGeneral", "DejaVu Serif"],
    "mathtext.fontset":  "stix",
    "axes.edgecolor":    "#4A4A4A",
    "axes.linewidth":    0.8,
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "axes.grid":         True,
    "grid.color":        "#E4E4E4",
    "grid.linewidth":    0.5,
    "axes.axisbelow":    True,
    "xtick.color":       "#333333",
    "ytick.color":       "#333333",
    "text.color":        "#1A1A1A",
    "axes.labelcolor":   "#1A1A1A",
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 11,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
})

# ── colour palette ───────────────────────────────────────────────────────────
# Okabe & Ito (2008) colourblind-safe qualitative palette, the de facto
# standard for scientific figures; validated with the project's palette
# checker (CVD separation, contrast, chroma floor all pass).
C_TRIVY = "#0072B2"  # blue
C_GRYPE = "#009E73"  # bluish green
C_OSV   = "#D55E00"  # vermillion
C_A, C_B, C_C = "#A6447A", "#B36A00", "#0B72A8"  # plum, ochre, steel blue
GROUP_COLOUR = {"A": C_A, "B": C_B, "C": C_C}

# Group order matches the tables in Chapter 5 (A, then B, then C) so that a
# reader cross-referencing a figure against Table 5.1 or 5.2 on the facing
# page meets the images in the same sequence.
ORDER = [
    "vulnerables_web-dvwa", "bkimminich_juice-shop",
    "nginx_1.19", "node_14", "python_3.8",
    "alpine_3.19", "nginx_1.29.7", "node_20", "python_3.12",
]
LABEL = {
    "alpine_3.19": "alpine:3.19",
    "nginx_1.29.7": "nginx:1.29.7",   # nginx:1.29.7 @sha256:7150b3a3 (2026-03-31)
    "node_20": "node:20", "python_3.12": "python:3.12",
    "nginx_1.19": "nginx:1.19", "node_14": "node:14",
    "python_3.8": "python:3.8",
    "vulnerables_web-dvwa": "web-dvwa",
    "bkimminich_juice-shop": "juice-shop",
}
# group background spans (index ranges, inclusive)
SPANS = {"A": (0, 1), "B": (2, 4), "C": (5, 8)}

# Boundaries between maintenance-state groups, drawn as thin rules. The
# group labels alone left nothing marking where one group ends and the
# next begins.
GROUP_EDGES = [1.5, 4.5]

def group_rules(ax, offset=0.0):
    """Tint each maintenance-state group's band of the plot.

    Rules drawn between groups cut through the rotated tick labels; a tint
    marks the same regions without crossing any text. The colour matches
    each group's label underneath.
    """
    for grp, (lo, hi) in SPANS.items():
        ax.axvspan(lo - 0.5 + offset, hi + 0.5 + offset,
                   color=GROUP_COLOUR[grp], alpha=0.10, zorder=0,
                   linewidth=0)

def group_bg(ax, n_bars=1, pad=0.5):
    """Shade group regions on ax."""
    for grp, (lo, hi) in SPANS.items():
        ax.axvspan(lo - pad, hi + n_bars * 0.3 + pad,
                   alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)

def save(fig, name):
    path = os.path.join(OUT, name)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    fig.savefig(os.path.splitext(path)[0] + ".pdf", bbox_inches="tight")
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
    "alpine_3.19": 6,  "nginx_1.29.7": 169, "node_20": 2268,  "python_3.12": 1751,
    "nginx_1.19":  424,"node_14": 1439,     "python_3.8": 5660,
    "vulnerables_web-dvwa": 1575, "bkimminich_juice-shop": 98,
}
RAW_GRYPE = {
    "alpine_3.19": 10, "nginx_1.29.7": 172, "node_20": 1474,  "python_3.12": 1418,
    "nginx_1.19":  550,"node_14": 1995,     "python_3.8": 2533,
    "vulnerables_web-dvwa": 2097, "bkimminich_juice-shop": 93,
}
RAW_OSV = {
    "alpine_3.19": 6,  "nginx_1.29.7": 177, "node_20": 1458,  "python_3.12": 1422,
    "nginx_1.19":  132,"node_14": 210,      "python_3.8": 2620,
    "vulnerables_web-dvwa": 336, "bkimminich_juice-shop": 94,
}
RAW_TRIVY_FIX = {
    "alpine_3.19": 100,"nginx_1.29.7": 0,  "node_20": 1,     "python_3.12": 14,
    "nginx_1.19":  79, "node_14": 77,      "python_3.8": 60,
    "vulnerables_web-dvwa": 88, "bkimminich_juice-shop": 85,
}
RAW_GRYPE_FIX = {
    "alpine_3.19": 60, "nginx_1.29.7": 0,  "node_20": 1,     "python_3.12": 18,
    "nginx_1.19":  58, "node_14": 34,      "python_3.8": 41,
    "vulnerables_web-dvwa": 65, "bkimminich_juice-shop": 84,
}
RAW_TRIVY_CRIT = {
    "alpine_3.19": 0, "nginx_1.29.7": 0, "node_20": 33,  "python_3.12": 0,
    "nginx_1.19": 42, "node_14": 22,     "python_3.8": 182,
    "vulnerables_web-dvwa": 254, "bkimminich_juice-shop": 10,
}
RAW_GRYPE_CRIT = {
    "alpine_3.19": 0, "nginx_1.29.7": 0, "node_20": 32,  "python_3.12": 0,
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

fig, ax = plt.subplots(figsize=(6.4, 4.0))
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
group_rules(ax, offset=width)
for grp, (lo, hi) in SPANS.items():
    ax.text((lo+hi)/2 + 0.15, -0.24, f"Group {grp}",
            transform=ax.get_xaxis_transform(), ha="center", va="top",
            fontsize=10, color=GROUP_COLOUR[grp], fontweight="bold",
            clip_on=False)

ax.set_yscale("log")
ax.set_ylabel("Scan time (seconds, log scale)", fontsize=9)
ax.set_xticks(x + width)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=10)
ax.legend(fontsize=10, loc="upper center", ncol=3, frameon=False,
          bbox_to_anchor=(0.5, 1.12))
ax.yaxis.grid(True, which="major", linestyle="-", alpha=0.18, zorder=0)
ax.set_axisbelow(True)
save(fig, "fig1_performance.png")

# ── Fig 2: Findings by severity — stacked bars (Trivy vs Grype) ──────────────
print("Fig 2: Findings by severity (stacked)…")
SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLOUR = {
    "CRITICAL": "#7F1D1D",  # deep red
    "HIGH":     "#DC2626",  # red
    "MEDIUM":   "#F59E0B",  # amber
    "LOW":      "#94A3B8",  # slate (also absorbs NEGLIGIBLE + UNKNOWN)
}

def sev_stack(counts):
    """Return [CRITICAL, HIGH, MEDIUM, LOW] folding NEGLIGIBLE+UNKNOWN into LOW."""
    low = counts.get("LOW", 0) + counts.get("NEGLIGIBLE", 0) + counts.get("UNKNOWN", 0)
    return [counts.get("CRITICAL", 0), counts.get("HIGH", 0),
            counts.get("MEDIUM", 0), low]

x = np.arange(len(ORDER))
width = 0.38
fig, ax = plt.subplots(figsize=(6.4, 4.0))

trivy_stacks = np.array([sev_stack(by_safe[s]["trivy_counts"]) for s in ORDER])
grype_stacks = np.array([sev_stack(by_safe[s]["grype_counts"]) for s in ORDER])

bottom_t = np.zeros(len(ORDER))
bottom_g = np.zeros(len(ORDER))
for i, sev in enumerate(SEV_ORDER):
    ax.bar(x - width/2, trivy_stacks[:, i], width, bottom=bottom_t,
           color=SEV_COLOUR[sev], edgecolor="white", linewidth=0.4,
           label=sev if sev != "LOW" else "LOW (incl. negligible/unknown)")
    ax.bar(x + width/2, grype_stacks[:, i], width, bottom=bottom_g,
           color=SEV_COLOUR[sev], edgecolor="white", linewidth=0.4)
    bottom_t += trivy_stacks[:, i]
    bottom_g += grype_stacks[:, i]

# annotate tool label above each bar
totals_t = trivy_stacks.sum(axis=1)
totals_g = grype_stacks.sum(axis=1)
for i in range(len(ORDER)):
    ax.text(i - width/2, totals_t[i] * 1.05, "T", ha="center", va="bottom",
            fontsize=9, color=C_TRIVY, fontweight="bold")
    ax.text(i + width/2, totals_g[i] * 1.05, "G", ha="center", va="bottom",
            fontsize=9, color=C_GRYPE, fontweight="bold")

ax.set_yscale("log")
ax.set_ylim(top=max(totals_t.max(), totals_g.max()) * 4.0)
group_rules(ax)
for grp, (lo, hi) in SPANS.items():
    ax.text((lo+hi)/2, -0.34, f"Group {grp}",
            transform=ax.get_xaxis_transform(), ha="center", va="top",
            fontsize=9, color=GROUP_COLOUR[grp], fontweight="bold",
            clip_on=False)
ax.set_ylabel("Findings per image (log scale)", fontsize=9)
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=10)
ax.legend(fontsize=10, loc="lower left", ncol=4, frameon=False,
          bbox_to_anchor=(0.0, 1.01))
ax.yaxis.grid(True, which="both", linestyle="--", alpha=0.4)
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

fig, axes = plt.subplots(1, 2, figsize=(6.5, 4.0))

# left: Jaccard bars
ax = axes[0]
bars = ax.bar(range(len(ORDER)), jaccards, color=bar_col, alpha=0.85, zorder=3)
ax.set_ylabel("Jaccard similarity", fontsize=9)
ax.set_xticks(range(len(ORDER)))
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=40, ha="right", fontsize=10)
ax.set_ylim(0, 1.12)
ax.yaxis.grid(True, linestyle="-", alpha=0.18); ax.set_axisbelow(True)
group_rules(ax)
for grp, (lo, hi) in SPANS.items():
    ax.text((lo+hi)/2, -0.34, f"Group {grp}",
            transform=ax.get_xaxis_transform(), ha="center", va="top",
            fontsize=9, color=GROUP_COLOUR[grp], fontweight="bold",
            clip_on=False)

# right: stacked composition
ax = axes[1]
ax.bar(range(len(ORDER)), both_pct, color="#6B7280", alpha=0.85, label="Shared (both)")
ax.bar(range(len(ORDER)), t_pct, bottom=both_pct, color=C_TRIVY, alpha=0.75, label="Trivy only")
ax.bar(range(len(ORDER)), g_pct,
       bottom=[b+t for b,t in zip(both_pct, t_pct)],
       color=C_GRYPE, alpha=0.75, label="Grype only")
ax.set_ylabel("% of unique CVEs", fontsize=9)
ax.set_xticks(range(len(ORDER)))
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=40, ha="right", fontsize=10)
ax.set_ylim(0, 112); ax.legend(fontsize=10, loc="upper center", frameon=False,
                              ncol=3, bbox_to_anchor=(0.5, 1.13),
                              columnspacing=1.4, handlelength=1.4)
ax.yaxis.grid(True, linestyle="-", alpha=0.18); ax.set_axisbelow(True)
# same group markers and rules as the left panel: the right panel's bars
# are coloured by set membership, not by group, so without these the
# maintenance-state split is only readable on one of the two panels.
group_rules(ax)
for grp, (lo, hi) in SPANS.items():
    ax.text((lo+hi)/2, -0.34, f"Group {grp}",
            transform=ax.get_xaxis_transform(), ha="center", va="top",
            fontsize=9, color=GROUP_COLOUR[grp], fontweight="bold",
            clip_on=False)
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

fig, ax = plt.subplots(figsize=(6.4, 4.0))
ax.bar(x - width, ag_pct, width, label="Same severity",  color="#6B7280", alpha=0.85)
ax.bar(x,         th_pct, width, label="Trivy higher",   color=C_TRIVY,   alpha=0.85)
ax.bar(x + width, gh_pct, width, label="Grype higher",   color=C_GRYPE,   alpha=0.85)


# annotate agree% and shared count
for i, (v, n) in enumerate(zip(ag_pct, shared_n)):
    ax.text(i - width, v + 1.5, f"{v:.0f}%", ha="center", va="bottom", fontsize=10)
    ax.text(i, -7, f"n={n}", ha="center", va="top", fontsize=9, color="grey")

ax.set_ylabel("% of shared CVEs", fontsize=9)
ax.set_ylim(0, 115)
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=10)
ax.legend(fontsize=11)
ax.yaxis.grid(True, linestyle="-", alpha=0.18); ax.set_axisbelow(True)
save(fig, "fig4_severity_agreement.png")

# ── Fig 5: Fix rates ──────────────────────────────────────────────────────────
print("Fig 5: Fix rates…")
x = np.arange(len(ORDER))
width = 0.35

fig, ax = plt.subplots(figsize=(6.4, 4.0))
ax.bar(x - width/2, [RAW_TRIVY_FIX[s] for s in ORDER], width,
       label="Trivy fix%", color=C_TRIVY, alpha=0.85)
ax.bar(x + width/2, [RAW_GRYPE_FIX[s] for s in ORDER], width,
       label="Grype fix%", color=C_GRYPE, alpha=0.85)


for i, s in enumerate(ORDER):
    tv, gv = RAW_TRIVY_FIX[s], RAW_GRYPE_FIX[s]
    ax.text(i - width/2, tv + 1.5, f"{tv}%", ha="center", va="bottom", fontsize=10)
    ax.text(i + width/2, gv + 1.5, f"{gv}%", ha="center", va="bottom", fontsize=10)

ax.set_ylabel("% of findings with a fix available", fontsize=9)
ax.set_ylim(0, 115)
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=10)
ax.legend(fontsize=11)
ax.yaxis.grid(True, linestyle="-", alpha=0.18); ax.set_axisbelow(True)
group_rules(ax)
for grp, (lo, hi) in SPANS.items():
    ax.text((lo+hi)/2, -0.34, f"Group {grp}",
            transform=ax.get_xaxis_transform(), ha="center", va="top",
            fontsize=9, color=GROUP_COLOUR[grp], fontweight="bold",
            clip_on=False)
save(fig, "fig5_fix_rates.png")

# ── Fig 6: CRITICAL counts ────────────────────────────────────────────────────
print("Fig 6: CRITICAL counts…")
x = np.arange(len(ORDER))
width = 0.35

fig, ax = plt.subplots(figsize=(6.4, 3.4))
ax.bar(x - width/2, [RAW_TRIVY_CRIT[s] for s in ORDER], width,
       label="Trivy CRITICAL", color=C_TRIVY, alpha=0.85)
ax.bar(x + width/2, [RAW_GRYPE_CRIT[s] for s in ORDER], width,
       label="Grype CRITICAL", color=C_GRYPE, alpha=0.85)


for i, s in enumerate(ORDER):
    tv, gv = RAW_TRIVY_CRIT[s], RAW_GRYPE_CRIT[s]
    if tv > 0: ax.text(i - width/2, tv + 3, str(tv), ha="center", va="bottom", fontsize=10)
    if gv > 0: ax.text(i + width/2, gv + 3, str(gv), ha="center", va="bottom", fontsize=10)

ax.set_ylabel("CRITICAL vulnerability count", fontsize=9)
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=10)
ax.legend(fontsize=11)
ax.yaxis.grid(True, linestyle="-", alpha=0.18); ax.set_axisbelow(True)
save(fig, "fig6_critical_counts.png")

# ── Fig 7: CWE top 10 ─────────────────────────────────────────────────────────
print("Fig 7: CWE top 10…")

# aggregate CWE counts across all images
trivy_cwe_agg = collections.Counter()
grype_cwe_agg = collections.Counter()
for r in tables:
    for cwe, cnt in r["trivy_cwes"].items(): trivy_cwe_agg[cwe] += cnt
    for cwe, cnt in r["grype_cwes"].items(): grype_cwe_agg[cwe] += cnt

top_cwes = [c for c, _ in (trivy_cwe_agg + grype_cwe_agg).most_common(20)]
CWE_NAMES = {
    "CWE-476": "NULL Ptr Deref",       "CWE-416": "Use After Free",
    "CWE-125": "OOB Read",             "CWE-787": "OOB Write",
    "CWE-190": "Integer Overflow",     "CWE-119": "Memory Ops",
    "CWE-401": "Memory Leak",          "CWE-400": "Resource Exhaustion",
    "CWE-362": "Race Condition",       "CWE-122": "Heap Buffer Overflow",
    "CWE-120": "Classic Buffer Overflow", "CWE-667": "Improper Locking",
    "CWE-20":  "Improper Input Validation", "CWE-415": "Double Free",
    "CWE-908": "Uninitialised Resource",   "CWE-835": "Infinite Loop",
    "CWE-770": "Alloc Without Limits",     "CWE-674": "Uncontrolled Recursion",
    "CWE-369": "Divide By Zero",           "CWE-404": "Improper Resource Shutdown",
}
xlabels = [f"{c} {CWE_NAMES.get(c, '')}".strip() for c in top_cwes]
t_vals  = [trivy_cwe_agg[c] for c in top_cwes]
g_vals  = [grype_cwe_agg[c] for c in top_cwes]

x = np.arange(len(top_cwes))
width = 0.35

# Horizontal bars: the CWE names are long, and rotating them on an x-axis
# spent roughly 40% of the figure height on labels alone.
fig, ax = plt.subplots(figsize=(6.4, 7.4))
ax.barh(x - width/2, t_vals, width, label="Trivy", color=C_TRIVY, alpha=0.85)
ax.barh(x + width/2, g_vals, width, label="Grype", color=C_GRYPE, alpha=0.85)

for i, (tv, gv) in enumerate(zip(t_vals, g_vals)):
    ax.text(max(tv, gv) + 18, i, f"\u03a3{tv + gv}",
            ha="left", va="center", fontsize=9, fontweight="bold")

ax.set_xlabel("Occurrence count (all 9 images)", fontsize=10)
ax.set_yticks(x)
ax.set_yticklabels(xlabels, fontsize=9)
ax.invert_yaxis()
ax.set_xlim(0, max(max(t_vals), max(g_vals)) * 1.22)
ax.legend(fontsize=10, loc="lower right", framealpha=0.95)
ax.xaxis.grid(True, linestyle="-", alpha=0.18)
ax.yaxis.grid(False); ax.set_axisbelow(True)
save(fig, "fig7_cwe_top20.png")

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

fig, ax = plt.subplots(figsize=(6.4, 4.0))

# Log y: on a linear axis spanning 0-100s every Trivy point sits on zero and
# the flat trend the figure exists to show is invisible.
for means, col, mark, lbl, _dy in [(t_means, C_TRIVY, "o", "Trivy", -3),
                                   (g_means, C_GRYPE, "s", "Grype", 8),
                                   (o_means, C_OSV,   "^", "OSV-Scanner", -13)]:
    ax.scatter(sizes, means, color=col, label=lbl, s=55, marker=mark,
               zorder=4, alpha=0.9, edgecolor="white", linewidth=0.6)
    coeffs = np.polyfit(sizes, means, 1)
    xs = np.linspace(min(sizes), max(sizes)*1.02, 200)
    ax.plot(xs, np.polyval(coeffs, xs), color=col, linestyle="--",
            alpha=0.55, linewidth=1.1, zorder=3)
    # slope in ms per MB says the same thing as the fitted line, in a number
    ax.annotate(f"{coeffs[0]*1000:,.0f} ms/MB", (xs[-1], np.polyval(coeffs, xs[-1])),
                textcoords="offset points", xytext=(6, _dy), fontsize=9,
                color=col, fontweight="bold", annotation_clip=False)

ax.set_yscale("log")
ax.set_xlabel("Image size (MB)", fontsize=10)
ax.set_ylabel("Mean scan time (seconds, log scale)", fontsize=10)
ax.set_xlim(-40, max(sizes)*1.30)
ax.legend(fontsize=10, loc="lower right", framealpha=0.95)
ax.yaxis.grid(True, which="major", linestyle="-", alpha=0.18)
ax.xaxis.grid(False)
ax.set_axisbelow(True)
save(fig, "fig8_time_vs_size.png")

print(f"\nDone — 8 graphs saved to {OUT}/")

# ── Fig 9: Box plots — one subplot per scanner, images on x-axis ──────────────
print("Fig 9: Scan-time box plots…")

tools_cfg = [("trivy", C_TRIVY, "Trivy"),
             ("grype",  C_GRYPE, "Grype"),
             ("osv",    C_OSV,   "OSV-Scanner")]
IMG_GROUPS = ["C","C","C","C","B","B","B","A","A"]

fig, axes = plt.subplots(3, 1, figsize=(6.5, 6.4), sharex=True)
fig.subplots_adjust(hspace=0.12)

fmt9 = matplotlib.ticker.FuncFormatter(
    lambda v, _: f"{v:.0f}s" if v >= 1 else f"{v:.2f}s"
)

xs = np.arange(len(ORDER))

for ax, (tool, col_hex, tool_lbl) in zip(axes, tools_cfg):
    run_lists = [[r / 1000 for r in bb[s][tool]["runs_ms"]] for s in ORDER]
    bp = ax.boxplot(
        run_lists,
        positions=xs,
        widths=0.55,
        patch_artist=True,
        whis=[5, 95],
        boxprops=dict(facecolor=col_hex, alpha=0.65),
        medianprops=dict(color="black", linewidth=2.2),
        whiskerprops=dict(color=col_hex, linewidth=1.3),
        capprops=dict(color=col_hex, linewidth=1.3),
        flierprops=dict(markerfacecolor=col_hex, marker=".", markersize=4, alpha=0.5),
        zorder=3,
    )
    ax.set_yscale("log")
    ax.set_ylabel("Scan time", fontsize=11)
    ax.yaxis.set_major_formatter(fmt9)
    ax.yaxis.grid(True, which="major", linestyle="-", alpha=0.18, zorder=0)
    ax.set_axisbelow(True)

    # group background bands
    for grp, lo_i, hi_i in [("C", 0, 3), ("B", 4, 6), ("A", 7, 8)]:
        ax.axvspan(lo_i - 0.5, hi_i + 0.5,
                   alpha=0.08, color=GROUP_COLOUR[grp], zorder=0)

    # scanner label inside the panel
    ax.text(0.01, 0.97, tool_lbl, transform=ax.transAxes,
            fontsize=10, fontweight="bold", color=col_hex,
            va="top", ha="left")

# x-axis labels only on bottom panel
axes[-1].set_xticks(xs)
axes[-1].set_xticklabels([LABEL[s] for s in ORDER], rotation=30, ha="right", fontsize=11)

# group labels above the top panel
for grp, lo_i, hi_i in [("C", 0, 3), ("B", 4, 6), ("A", 7, 8)]:
    mid_x = (lo_i + hi_i) / 2
    axes[0].text(mid_x, 1.02, f"Group {grp}",
                 transform=axes[0].get_xaxis_transform(),
                 ha="center", va="bottom", fontsize=11,
                 fontweight="bold", color=GROUP_COLOUR[grp])

save(fig, "fig9_scan_boxplot.png")

n_images = len(ORDER)

# ── Fig 10: Package breakdown driving Jaccard divergence ─────────────────────
print("Fig 10: Package breakdown for Jaccard divergence…")

import collections as _col

BASE_RESULTS = os.path.join(ROOT, "data", "raw")


def _pkg_breakdown(safe):
    """Return (t_only_pkgs, g_only_pkgs) as Counters."""
    with open(os.path.join(BASE_RESULTS, "trivy", f"{safe}_trivy.json")) as f:
        tj = json.load(f)
    with open(os.path.join(BASE_RESULTS, "grype", f"{safe}_grype.json")) as f:
        gj = json.load(f)

    t_vulns = {}
    for r in tj.get("Results", []):
        for v in (r.get("Vulnerabilities") or []):
            vid = v.get("VulnerabilityID", "")
            if vid:
                t_vulns[vid] = v.get("PkgName", "unknown")

    g_ids_exp = set()
    g_vulns   = {}
    for m in gj.get("matches", []):
        v   = m.get("vulnerability", {})
        vid = v.get("id", "")
        if vid:
            related = [r.get("id", "") for r in m.get("relatedVulnerabilities", [])
                       if r.get("id", "").startswith("CVE-")]
            g_vulns[vid] = m.get("artifact", {}).get("name", "unknown")
            g_ids_exp.add(vid)
            g_ids_exp.update(related)

    t_ids   = set(t_vulns.keys())
    t_only  = t_ids - g_ids_exp
    g_ponly = {vid for vid in g_vulns if vid not in t_ids}

    t_pkgs = _col.Counter(t_vulns[c] for c in t_only if c in t_vulns)
    g_pkgs = _col.Counter(g_vulns[c] for c in g_ponly)
    return t_pkgs, g_pkgs


pkg_data = {s: _pkg_breakdown(s) for s in ORDER}

all_t_pkgs = _col.Counter()
all_g_pkgs = _col.Counter()
for s in ORDER:
    all_t_pkgs.update(pkg_data[s][0])
    all_g_pkgs.update(pkg_data[s][1])

TOP_N      = 5
top_t_pkgs = [p for p, _ in all_t_pkgs.most_common(TOP_N)]
top_g_pkgs = [p for p, _ in all_g_pkgs.most_common(TOP_N)]

# Colour palettes for each direction
COLORS_T = ["#DC2626", "#EA580C", "#D97706", "#65A30D", "#0891B2", "#9CA3AF"]
COLORS_G = ["#1D4ED8", "#7C3AED", "#DB2777", "#059669", "#B45309", "#9CA3AF"]

from matplotlib.colors import LogNorm as _LogNorm

def _build_matrix(pkg_list, side):
    cols = pkg_list + ["other"]
    data = np.zeros((len(ORDER), len(cols)))
    for i, s in enumerate(ORDER):
        ctr = pkg_data[s][side]
        for j, pkg in enumerate(cols):
            if pkg == "other":
                known = sum(ctr.get(p, 0) for p in pkg_list)
                data[i, j] = max(0, sum(ctr.values()) - known)
            else:
                data[i, j] = ctr.get(pkg, 0)
    return data, cols

t_mat, t_cols = _build_matrix(top_t_pkgs, 0)
g_mat, g_cols = _build_matrix(top_g_pkgs, 1)

# Concentration, not composition. The claim is that Trivy's exclusive CVEs
# pile into a single package while Grype's do not, which is one number per
# tool per image: the share contributed by that tool's largest single
# package. Plotting composition instead forced an "other" bucket that was
# the largest entry on several rows and told the reader nothing.
fig, ax = plt.subplots(figsize=(6.4, 4.2))

y = np.arange(len(ORDER))
bar_h = 0.38

# The count matters as much as the share: 100% of two findings is not
# concentration, so each label carries the denominator.
t_share, g_share, t_top, g_top = [], [], [], []
for sfe in ORDER:
    tc, gc = pkg_data[sfe]
    tt, gt = sum(tc.values()), sum(gc.values())
    t_share.append(100 * max(tc.values()) / tt if tt else 0.0)
    g_share.append(100 * max(gc.values()) / gt if gt else 0.0)
    t_top.append(f"{tc.most_common(1)[0][0]}  n={tt:,}" if tc else "")
    g_top.append(f"{gc.most_common(1)[0][0]}  n={gt:,}" if gc else "")

ax.barh(y - bar_h/2, t_share, bar_h, color=C_TRIVY, alpha=0.9,
        label="Trivy-only findings")
ax.barh(y + bar_h/2, g_share, bar_h, color=C_GRYPE, alpha=0.9,
        label="Grype-only findings")

for i in range(len(ORDER)):
    if t_share[i] > 0:
        ax.text(t_share[i] + 1.5, i - bar_h/2, t_top[i], va="center",
                ha="left", fontsize=8, color=C_TRIVY)
    if g_share[i] > 0:
        ax.text(g_share[i] + 1.5, i + bar_h/2, g_top[i], va="center",
                ha="left", fontsize=8, color=C_GRYPE)

ax.set_yticks(y)
ax.set_yticklabels([LABEL[sfe] for sfe in ORDER], fontsize=9)
ax.invert_yaxis()
ax.set_xlim(0, 178)
ax.set_xticks([0, 20, 40, 60, 80, 100])
ax.set_xlabel("Share of that tool's exclusive CVEs from its single "
              "largest package (%)", fontsize=9)
ax.legend(fontsize=9, loc="lower right", frameon=False)
ax.xaxis.grid(True, linestyle="-", alpha=0.18)
ax.yaxis.grid(False)
ax.set_axisbelow(True)
for side in ("top", "right"):
    ax.spines[side].set_visible(False)

save(fig, "fig10_jaccard_packages.png")

print(f"\nDone — 10 graphs saved to {OUT}/")
