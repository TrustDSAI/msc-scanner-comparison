#!/usr/bin/env python3
"""
Export figures 1, 2, 3, 5, 7 as PDF without embedded titles for the article.
Outputs to /root/esem-article/figs/
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
OUT    = "/root/esem-article/figs"
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
    "grid.color":        "#D8D8D8",
    "grid.linewidth":    0.5,
    "axes.axisbelow":    True,
    "xtick.color":       "#333333",
    "ytick.color":       "#333333",
    "text.color":        "#1A1A1A",
    "axes.labelcolor":   "#1A1A1A",
    "font.size":         13,
    "axes.titlesize":    15,
    "axes.labelsize":    14,
    "xtick.labelsize":   13,
    "ytick.labelsize":   13,
    "legend.fontsize":   13,
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

ORDER = [
    "alpine_3.19", "nginx_1.29.7", "node_20", "python_3.12",
    "nginx_1.19", "node_14", "python_3.8",
    "vulnerables_web-dvwa", "bkimminich_juice-shop",
]
LABEL = {
    "alpine_3.19": "alpine:3.19", "nginx_1.29.7": "nginx:1.29.7",
    "node_20": "node:20", "python_3.12": "python:3.12",
    "nginx_1.19": "nginx:1.19", "node_14": "node:14",
    "python_3.8": "python:3.8",
    "vulnerables_web-dvwa": "web-dvwa",
    "bkimminich_juice-shop": "juice-shop",
}
SPANS = {"C": (0, 3), "B": (4, 6), "A": (7, 8)}

with open(BENCH)  as f: bench  = json.load(f)
with open(TABLES) as f: tables = json.load(f)

by_safe = {r["safe"]: r for r in tables}
bb      = {b["safe"]: b for b in bench}

def field(safe, *keys):
    v = by_safe[safe]
    for k in keys: v = v[k]
    return v

def save(fig, name):
    path = os.path.join(OUT, name)
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {name}")

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

# ── Fig 1: Scan performance ───────────────────────────────────────────────────
print("Fig 1: Scan performance…")
tools_cfg = [("trivy", C_TRIVY, "Trivy"), ("grype", C_GRYPE, "Grype"), ("osv", C_OSV, "OSV-Scanner")]
x = np.arange(len(ORDER))
width = 0.26

fig, ax = plt.subplots(figsize=(7.5, 4.2))
for i, (tool, col, lbl) in enumerate(tools_cfg):
    means, sds = [], []
    for safe in ORDER:
        b = bb[safe]
        runs = b[tool]["runs_ms"][1:] if safe == "alpine_3.19" and tool in ("trivy", "grype") else b[tool]["runs_ms"]
        m = np.mean(runs) / 1000
        s = (np.std(runs, ddof=1) if len(runs) > 1 else 0) / 1000
        means.append(m); sds.append(s)
    ax.bar(x + i*width, means, width, label=lbl, color=col, alpha=0.85, zorder=3)
    ax.errorbar(x + i*width, means, yerr=sds, fmt="none", color="black", capsize=3, linewidth=1, zorder=4)
    if tool == "trivy":
        for j, (m, s_) in enumerate(zip(means, sds)):
            ax.text(j + i*width, m * 1.5, f"{m*1000:.0f}ms", ha="center", va="bottom", fontsize=10, color=col)

for grp, (lo, hi) in SPANS.items():
    ax.axvspan(lo - 0.4, hi + 0.9, alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)
    ax.text((lo+hi)/2 + 0.15, 0.008, f"Grp {grp}", ha="center", va="bottom",
            fontsize=13, color=GROUP_COLOUR[grp], fontweight="bold")

ax.set_yscale("log")
ax.set_ylabel("Scan time (seconds, log scale)", fontsize=16)
ax.set_xticks(x + width)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=13)
ax.legend(fontsize=14)
ax.yaxis.grid(True, which="both", linestyle="--", alpha=0.4, zorder=0)
ax.set_axisbelow(True)
save(fig, "fig1_performance.pdf")

# ── Fig 2: Total findings ─────────────────────────────────────────────────────
print("Fig 2: Total findings…")
x = np.arange(len(ORDER))
width = 0.28

fig, ax = plt.subplots(figsize=(7.5, 4.2))
ax.bar(x - width, [RAW_TRIVY[s] for s in ORDER], width, label="Trivy", color=C_TRIVY, alpha=0.85)
ax.bar(x,          [RAW_GRYPE[s] for s in ORDER], width, label="Grype", color=C_GRYPE, alpha=0.85)
ax.bar(x + width,  [RAW_OSV[s]   for s in ORDER], width, label="OSV-Scanner†", color=C_OSV, alpha=0.85)

for grp, (lo, hi) in SPANS.items():
    ax.axvspan(lo - 0.55, hi + 0.95, alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)


ax.set_ylabel("Total vulnerability findings", fontsize=16)
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=13)
ax.legend(fontsize=14)
ax.yaxis.grid(True, linestyle="--", alpha=0.4)
ax.set_axisbelow(True)
save(fig, "fig2_total_findings.pdf")

# ── Fig 3: CVE overlap ────────────────────────────────────────────────────────
print("Fig 3: CVE overlap…")
jaccards  = [field(s, "overlap", "jaccard") for s in ORDER]
t_only    = [field(s, "overlap", "t_only")  for s in ORDER]
both      = [field(s, "overlap", "both")    for s in ORDER]
g_only    = [field(s, "overlap", "g_only")  for s in ORDER]
totals_ov = [a+b+c for a,b,c in zip(t_only, both, g_only)]
both_pct  = [b/tot*100 if tot else 0 for b,tot in zip(both, totals_ov)]
t_pct     = [t/tot*100 if tot else 0 for t,tot in zip(t_only, totals_ov)]
g_pct     = [g/tot*100 if tot else 0 for g,tot in zip(g_only, totals_ov)]
bar_col   = [GROUP_COLOUR[by_safe[s]["group"]] for s in ORDER]

fig, axes = plt.subplots(1, 2, figsize=(8.0, 4.2))

ax = axes[0]
bars = ax.bar(range(len(ORDER)), jaccards, color=bar_col, alpha=0.85, zorder=3)
ax.axhline(0.5, color="grey", linestyle="--", linewidth=1.2, alpha=0.7)
ax.set_ylabel("Jaccard similarity", fontsize=16)
ax.set_xticks(range(len(ORDER)))
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=40, ha="right", fontsize=13)
ax.set_ylim(0, 1.12)
ax.yaxis.grid(True, linestyle="--", alpha=0.4); ax.set_axisbelow(True)
for bar, val in zip(bars, jaccards):
    ax.text(bar.get_x()+bar.get_width()/2, val+0.02, f"{val:.3f}", ha="center", va="bottom", fontsize=13, fontweight="bold")
ax.legend(handles=[
    mpatches.Patch(color=C_A, label="Group A"),
    mpatches.Patch(color=C_B, label="Group B"),
    mpatches.Patch(color=C_C, label="Group C"),
], fontsize=13)

ax = axes[1]
ax.bar(range(len(ORDER)), both_pct, color="#6B7280", alpha=0.85, label="Shared (both)")
ax.bar(range(len(ORDER)), t_pct, bottom=both_pct, color=C_TRIVY, alpha=0.75, label="Trivy only")
ax.bar(range(len(ORDER)), g_pct, bottom=[b+t for b,t in zip(both_pct, t_pct)], color=C_GRYPE, alpha=0.75, label="Grype only")
ax.set_ylabel("% of unique CVEs", fontsize=16)
ax.set_xticks(range(len(ORDER)))
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=40, ha="right", fontsize=13)
ax.set_ylim(0, 110); ax.legend(fontsize=13)
ax.yaxis.grid(True, linestyle="--", alpha=0.4); ax.set_axisbelow(True)

save(fig, "fig3_cve_overlap.pdf")

# ── Fig 5: Fix rates ──────────────────────────────────────────────────────────
print("Fig 5: Fix rates…")
x = np.arange(len(ORDER))
width = 0.35

fig, ax = plt.subplots(figsize=(7.5, 4.2))
ax.bar(x - width/2, [RAW_TRIVY_FIX[s] for s in ORDER], width, label="Trivy fix%", color=C_TRIVY, alpha=0.85)
ax.bar(x + width/2, [RAW_GRYPE_FIX[s] for s in ORDER], width, label="Grype fix%", color=C_GRYPE, alpha=0.85)

for grp, (lo, hi) in SPANS.items():
    ax.axvspan(lo - 0.55, hi + 0.85, alpha=0.06, color=GROUP_COLOUR[grp], zorder=0)

for i, s in enumerate(ORDER):
    tv, gv = RAW_TRIVY_FIX[s], RAW_GRYPE_FIX[s]
    ax.text(i - width/2, tv + 1.5, f"{tv}%", ha="center", va="bottom", fontsize=12)
    ax.text(i + width/2, gv + 1.5, f"{gv}%", ha="center", va="bottom", fontsize=12)

ax.set_ylabel("% of findings with a fix available", fontsize=16)
ax.set_ylim(0, 115)
ax.set_xticks(x)
ax.set_xticklabels([LABEL[s] for s in ORDER], rotation=35, ha="right", fontsize=13)
ax.legend(fontsize=14)
ax.yaxis.grid(True, linestyle="--", alpha=0.4); ax.set_axisbelow(True)
save(fig, "fig5_fix_rates.pdf")

# ── Fig 7: CWE top 25 grouped by category ────────────────────────────────────
print("Fig 7: CWE top 25 (grouped by category)…")
trivy_cwe_agg = collections.Counter()
grype_cwe_agg = collections.Counter()
for r in tables:
    for cwe, cnt in r["trivy_cwes"].items(): trivy_cwe_agg[cwe] += cnt
    for cwe, cnt in r["grype_cwes"].items(): grype_cwe_agg[cwe] += cnt

combined_cwe = trivy_cwe_agg + grype_cwe_agg

# Top 25 by combined count
TOP_N = 25
top25 = [c for c, _ in combined_cwe.most_common(TOP_N)]

# Category → (display label, background colour)
CAT_META = {
    "Memory Safety":     ("Memory Safety",       "#FEE2E2"),
    "Resource Mgmt":     ("Resource Management", "#FEF3C7"),
    "Concurrency":       ("Concurrency",         "#ECFDF5"),
    "Initialisation":    ("Initialisation / State", "#EFF6FF"),
    "Input Validation":  ("Input Validation",    "#F5F3FF"),
    "Info Disclosure":   ("Information Disclosure", "#FFF7ED"),
}

CWE_CATEGORY = {
    "CWE-476": "Memory Safety",  "CWE-416": "Memory Safety",
    "CWE-125": "Memory Safety",  "CWE-787": "Memory Safety",
    "CWE-190": "Memory Safety",  "CWE-119": "Memory Safety",
    "CWE-122": "Memory Safety",  "CWE-120": "Memory Safety",
    "CWE-415": "Memory Safety",  "CWE-121": "Memory Safety",
    "CWE-401": "Resource Mgmt",  "CWE-400": "Resource Mgmt",
    "CWE-835": "Resource Mgmt",  "CWE-770": "Resource Mgmt",
    "CWE-674": "Resource Mgmt",  "CWE-404": "Resource Mgmt",
    "CWE-362": "Concurrency",    "CWE-667": "Concurrency",
    "CWE-908": "Initialisation", "CWE-369": "Initialisation",
    "CWE-617": "Initialisation",
    "CWE-20":  "Input Validation","CWE-22":  "Input Validation",
    "CWE-295": "Input Validation",
    "CWE-200": "Info Disclosure", "CWE-203": "Info Disclosure",
}

CWE_SHORT = {
    "CWE-476": "Null Pointer Dereference",
    "CWE-416": "Use After Free",
    "CWE-125": "Out-of-Bounds Read",
    "CWE-787": "Out-of-Bounds Write",
    "CWE-190": "Integer Overflow",
    "CWE-119": "Improper Buffer Operations",
    "CWE-401": "Memory Leak",
    "CWE-400": "Resource Exhaustion",
    "CWE-362": "Race Condition",
    "CWE-122": "Heap Buffer Overflow",
    "CWE-120": "Buffer Copy w/o Bounds Check",
    "CWE-667": "Improper Locking",
    "CWE-20":  "Improper Input Validation",
    "CWE-415": "Double Free",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-835": "Infinite Loop",
    "CWE-770": "Resource Allocation w/o Limits",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-369": "Divide by Zero",
    "CWE-404": "Improper Resource Shutdown",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-200": "Sensitive Information Exposure",
    "CWE-22":  "Path Traversal",
    "CWE-617": "Reachable Assertion",
    "CWE-295": "Improper Certificate Validation",
}

# Sort top25 by category order, then by combined count desc within category
CAT_ORDER = list(CAT_META.keys())
def sort_key(cwe):
    cat = CWE_CATEGORY.get(cwe, "ZZ")
    cat_idx = CAT_ORDER.index(cat) if cat in CAT_ORDER else 99
    return (cat_idx, -combined_cwe[cwe])

ordered = sorted(top25, key=sort_key)

ylabels  = [f"{c}: {CWE_SHORT.get(c, c)}" for c in ordered]
t_vals   = np.array([trivy_cwe_agg[c] for c in ordered], dtype=float)
g_vals   = np.array([grype_cwe_agg[c] for c in ordered], dtype=float)

# Build category boundary spans (row indices, bottom-up because imshow is top-down)
cat_spans = []
cur_cat = None
start = 0
for i, cwe in enumerate(ordered):
    cat = CWE_CATEGORY.get(cwe, "Other")
    if cat != cur_cat:
        if cur_cat is not None:
            cat_spans.append((cur_cat, start, i - 1))
        cur_cat = cat
        start = i
cat_spans.append((cur_cat, start, len(ordered) - 1))

height = 0.35
y = np.arange(len(ordered))

fig, ax = plt.subplots(figsize=(7.5, 6.8))

# Blended transform: x in axes fraction (0–1), y in data coords
from matplotlib.transforms import blended_transform_factory
blend = blended_transform_factory(ax.transAxes, ax.transData)

# Category background bands + centred label inside the band
for cat, lo, hi in cat_spans:
    bg = CAT_META.get(cat, ("", "#F9FAFB"))[1]
    ax.axhspan(lo - 0.5, hi + 0.5, color=bg, zorder=0, alpha=1.0)
    mid = (lo + hi) / 2
    label = CAT_META.get(cat, (cat,))[0]
    ax.text(0.5, mid, label, transform=blend,
            ha="center", va="center", fontsize=13, fontstyle="italic",
            fontweight="bold", color="#6B7280", alpha=0.55, zorder=2)

# Horizontal bars (drawn on top of the band label, zorder=3)
ax.barh(y + height/2, t_vals, height, label="Trivy",  color=C_TRIVY, alpha=0.85, zorder=3)
ax.barh(y - height/2, g_vals, height, label="Grype",  color=C_GRYPE, alpha=0.85, zorder=3)

# Σ annotations at end of longer bar
for i, (tv, gv) in enumerate(zip(t_vals, g_vals)):
    total = tv + gv
    x_pos = max(tv, gv) + 8
    ax.text(x_pos, y[i], f"Σ{int(total):,}", va="center", fontsize=10.5, color="#374151")

# Category separator lines
prev_cat = None
for i, cwe in enumerate(ordered):
    cat = CWE_CATEGORY.get(cwe, "Other")
    if cat != prev_cat and i > 0:
        ax.axhline(i - 0.5, color="#9CA3AF", linewidth=0.8, linestyle="--", zorder=4)
    prev_cat = cat

ax.set_yticks(y)
ax.set_yticklabels(ylabels, fontsize=13)
ax.invert_yaxis()
ax.set_xlabel("Occurrence count (all 9 images, aggregated)", fontsize=14)
ax.xaxis.grid(True, linestyle="--", alpha=0.4, zorder=0)
ax.set_axisbelow(True)
ax.legend(fontsize=14, loc="lower right")
plt.subplots_adjust(left=0.32)
save(fig, "fig7_cwe_top25.pdf")

# ── Fig 10a/10b: Package breakdown split into two figures ────────────────────
print("Fig 10: Package breakdown (split)…")

import collections as _col
from matplotlib.colors import LogNorm as _LogNorm

BASE_RESULTS = os.path.join(ROOT, "data", "raw")

def _pkg_breakdown(safe):
    with open(os.path.join(BASE_RESULTS, "trivy", f"{safe}_trivy.json")) as f: tj = json.load(f)
    with open(os.path.join(BASE_RESULTS, "grype", f"{safe}_grype.json")) as f: gj = json.load(f)
    t_vulns = {}
    for r in tj.get("Results", []):
        for v in (r.get("Vulnerabilities") or []):
            vid = v.get("VulnerabilityID", "")
            if vid: t_vulns[vid] = v.get("PkgName", "unknown")
    g_ids_exp = set(); g_vulns = {}
    for m in gj.get("matches", []):
        v = m.get("vulnerability", {}); vid = v.get("id", "")
        if vid:
            related = [r.get("id","") for r in m.get("relatedVulnerabilities",[]) if r.get("id","").startswith("CVE-")]
            g_vulns[vid] = m.get("artifact", {}).get("name", "unknown")
            g_ids_exp.add(vid); g_ids_exp.update(related)
    t_ids = set(t_vulns.keys()); t_only = t_ids - g_ids_exp
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

IMG_GROUPS = [by_safe[s]["group"] for s in ORDER]
ylabels = [LABEL[s] for s in ORDER]

def _build_matrix_n(pkg_list, side, include_other=True):
    cols = pkg_list + (["other"] if include_other else [])
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

def _heatmap_fig(mat, cols, cmap_name, ylabel_title, figsize=(7.5, 4.2)):
    fig, ax = plt.subplots(figsize=figsize)
    masked = np.where(mat == 0, np.nan, mat)
    pos_vals = mat[mat > 0]
    norm = _LogNorm(vmin=max(1, pos_vals.min()), vmax=pos_vals.max()) if len(pos_vals) else None
    cmap = matplotlib.cm.get_cmap(cmap_name).copy()
    cmap.set_bad("white")
    im = ax.imshow(masked, cmap=cmap, norm=norm, aspect="auto")
    plt.colorbar(im, ax=ax, label="CVE count (log scale)", shrink=0.85)
    ax.set_xticks(range(len(cols)))
    ax.set_xticklabels(cols, rotation=35, ha="right", fontsize=13)
    ax.set_yticks(range(len(ORDER)))
    ax.set_yticklabels(ylabels, fontsize=13)
    ax.set_ylabel(ylabel_title, fontsize=14)
    for i, tick in enumerate(ax.get_yticklabels()):
        tick.set_color(GROUP_COLOUR[IMG_GROUPS[i]])
        tick.set_fontweight("bold")
    for boundary in [3.5, 6.5]:
        ax.axhline(boundary, color="black", linewidth=1.5, zorder=5)
    if len(pos_vals):
        vmin_log = np.log(max(1, pos_vals.min()))
        vmax_log = np.log(pos_vals.max()) if pos_vals.max() > 0 else 1
        for i in range(len(ORDER)):
            for j in range(len(cols)):
                val = int(mat[i, j])
                if val == 0: continue
                norm_v = (np.log(val) - vmin_log) / (vmax_log - vmin_log) if vmax_log != vmin_log else 0.5
                ax.text(j, i, f"{val:,}", ha="center", va="center",
                        fontsize=12, color="white" if norm_v > 0.55 else "black")
    return fig

# Fig 10a: Trivy-exclusive — all 24 packages + "other"
top_t = [p for p, _ in all_t_pkgs.most_common()]
t_mat, t_cols = _build_matrix_n(top_t, 0, include_other=True)
fig = _heatmap_fig(t_mat, t_cols, "Reds", "Image", figsize=(max(7.5, len(t_cols)*0.42 + 2), 4.2))
save(fig, "fig10a_trivy_packages.pdf")

# Fig 10b: Grype-exclusive — top 30 packages + "other"
top_g = [p for p, _ in all_g_pkgs.most_common(30)]
g_mat, g_cols = _build_matrix_n(top_g, 1, include_other=True)
fig = _heatmap_fig(g_mat, g_cols, "Blues", "Image", figsize=(max(7.5, len(g_cols)*0.42 + 2), 4.2))
save(fig, "fig10b_grype_packages.pdf")

print("Done. PDFs written to", OUT)
