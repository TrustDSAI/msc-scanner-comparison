#!/usr/bin/env python3
"""Generate figures for the validation suite (Group V) section of Chapter 6."""

import json
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "validation", "results")
OUT     = os.path.join(ROOT, "figures")
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
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 11,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
})

# ── palette (matches generate_graphs.py) ──────────────────────────────────────
# Deepened traffic-light status triple (reserved semantics: block/review/pass).
# CVD separation is in the WARN band (6.9 protan) - acceptable here because
# every bar/region already carries a direct text label, not colour alone.
C_BLOCK  = "#B23A2E"   # deep red
C_REVIEW = "#B8860B"   # dark goldenrod
C_PASS   = "#1E8E5A"   # deep green
C_BLOCK_LIGHT  = "#E8A99F"
C_REVIEW_LIGHT = "#E8CE8A"

IMAGES = [
    ("v01-log4shell",     "v01: Log4Shell\n(CVE-2021-44228)",   "block"),
    ("v02-jenkins-2441",  "v02: Jenkins\n(CVE-2024-23897)",     "block"),
    ("v03-text4shell",    "v03: Text4Shell\n(CVE-2022-42889)",  "review"),
    ("v04-spring4shell",  "v04: Spring4Shell\n(CVE-2022-22965)","block"),
    ("v05-regresshion",   "v05: regreSSHion\n(CVE-2024-6387)",  "review"),
    ("v06-crit-low-epss", "v06: WebP/Pillow\n(CVE-2023-4863)",  "block"),
    ("v07-high-only",     "v07: HTTP/2 Reset\n(CVE-2023-44487)","block"),
    ("v08-eol-stretch",   "v08: Debian 9 EOL\n(multiple CVEs)", "review"),
    ("v09-distroless",    "v09: Distroless\n(no findings)",     "pass"),
    ("v10-alpine-current","v10: Alpine 3.21\n(no findings)",    "pass"),
    ("v11-corroborated-critical", "v11: zlib\n(CVE-2022-37434)", "block"),
]

TIER_COLOUR = {"block": C_BLOCK, "review": C_REVIEW, "pass": C_PASS,
               "unknown": "#9CA3AF"}

def load_result(image_id):
    path = os.path.join(RESULTS, f"{image_id}.json")
    if not os.path.exists(path):
        return {"block": [], "review": [], "decision": "unknown"}
    with open(path) as f:
        return json.load(f)


# ── Figure 11: Tier summary (categorical heatmap-style) ─────────────────────
print("Fig 11: Validation tier summary…")

fig, axes = plt.subplots(1, 2, figsize=(6.5, 7.0),
                         gridspec_kw={"width_ratios": [1, 2.2]})

# Left panel: tier indicator per image
ax_tier = axes[0]
tier_order = list(reversed(IMAGES))  # top = v01
tier_labels = [label for _, label, _ in tier_order]
tier_values  = [load_result(img_id).get("decision", "unknown")
                for img_id, _, _ in tier_order]
tier_colours  = [TIER_COLOUR[t] for t in tier_values]

y_pos = np.arange(len(tier_order))
bars = ax_tier.barh(y_pos, [1]*len(tier_order), height=0.7,
                    color=tier_colours, alpha=0.85, edgecolor="white", linewidth=0.5)

for i, (yp, tier) in enumerate(zip(y_pos, tier_values)):
    ax_tier.text(0.5, yp, tier.upper(), ha="center", va="center",
                 color="white", fontweight="bold", fontsize=10)

ax_tier.set_yticks(y_pos)
ax_tier.set_yticklabels(tier_labels, fontsize=10)
ax_tier.set_xlim(0, 1)
ax_tier.set_xticks([])
ax_tier.set_xlabel("Gate decision", fontsize=10)
ax_tier.set_title("(a) Tier per image", fontsize=11, fontweight="bold")
for spine in ["top", "right", "bottom"]:
    ax_tier.spines[spine].set_visible(False)

# Right panel: stacked bar chart (block + review counts)
ax_bar = axes[1]

block_counts  = []
review_counts = []
for img_id, _, _ in tier_order:
    res = load_result(img_id)
    block_counts.append(len(res.get("block", [])))
    review_counts.append(len(res.get("review", [])))

# Use log scale so v02's 191 review doesn't swamp everything
# Compute bar widths in log-space; use broken-axis annotation instead
max_review = max(review_counts)
ax_bar.barh(y_pos, block_counts, height=0.7, color=C_BLOCK, alpha=0.85,
            label="Block", edgecolor="white", linewidth=0.5)
ax_bar.barh(y_pos, review_counts, height=0.7, left=block_counts,
            color=C_REVIEW, alpha=0.7, label="Review",
            edgecolor="white", linewidth=0.5)

# Annotate counts on bars
for i, (b, r) in enumerate(zip(block_counts, review_counts)):
    total = b + r
    if b > 0:
        ax_bar.text(b / 2, i, str(b), ha="center", va="center",
                    color="white", fontsize=10, fontweight="bold")
    if r > 0:
        x_mid = b + r / 2
        # only annotate if bar wide enough to fit label
        if r >= 2:
            ax_bar.text(x_mid, i, str(r), ha="center", va="center",
                        color="white" if r > 5 else "#92400E", fontsize=10)

ax_bar.set_yticks(y_pos)
ax_bar.set_yticklabels([])
ax_bar.set_xscale("symlog", linthresh=1)
ax_bar.set_xlabel("Finding count (symlog scale)", fontsize=10)
ax_bar.set_title("(b) Block and review finding counts", fontsize=11, fontweight="bold")
ax_bar.legend(handles=[
    mpatches.Patch(color=C_BLOCK,  alpha=0.85, label="Block tier"),
    mpatches.Patch(color=C_REVIEW, alpha=0.7,  label="Review tier"),
], loc="upper right", fontsize=9, frameon=False, ncol=2,
              bbox_to_anchor=(1.0, 1.10))
for spine in ["top", "right"]:
    ax_bar.spines[spine].set_visible(False)

plt.tight_layout()
fig.savefig(os.path.join(OUT, "fig11_validation_outcomes.png"),
            dpi=150, bbox_inches="tight")
fig.savefig(os.path.join(OUT, "fig11_validation_outcomes.pdf"),
            dpi=150, bbox_inches="tight")
plt.close(fig)
print("  Saved fig11_validation_outcomes.png")


# ── Figure 12: Gate path coverage ─────────────────────────────────────────────
print("Fig 12: Gate path coverage…")

PATH_LABELS = {
    "kev_fix":               "KEV + fix\n(confirmed exploitation, remediation available)",
    "review_crit":           "REVIEW: CRITICAL not block-qualifying\n(no KEV, EPSS < 0.5 or consensus missing)",
    "review_high":           "REVIEW: HIGH + consensus\n(P7 path, severity-agnostic EPSS gate)",
    "review_crit_eol_context":"REVIEW: CRITICAL + EOL context\n(EOL as metadata, not gate trigger)",
    "review_corroborated":   "REVIEW: corroborated CRITICAL\n(all six signals, EPSS below the block bar)",
    "pass_clean":            "PASS: no actionable findings",
}

IMAGE_PATHS = [
    ("v01-log4shell",     "kev_fix"),
    ("v02-jenkins-2441",  "kev_fix"),
    ("v03-text4shell",    "review_crit"),
    ("v04-spring4shell",  "kev_fix"),
    ("v05-regresshion",   "review_high"),
    ("v06-crit-low-epss", "kev_fix"),
    ("v07-high-only",     "kev_fix"),
    ("v08-eol-stretch",   "review_crit_eol_context"),
    ("v09-distroless",    "pass_clean"),
    ("v10-alpine-current","pass_clean"),
    ("v11-corroborated-critical", "review_corroborated"),
]

# Count images per gate path
from collections import Counter
path_counts = Counter(p for _, p in IMAGE_PATHS)

# Use a horizontal bar chart ordered by path group (block > review > pass)
path_order = ["kev_fix", "review_corroborated", "review_crit", "review_high",
              "review_crit_eol_context", "pass_clean"]
path_tiers  = {"kev_fix": "block", "review_crit": "review", "review_high": "review",
               "review_corroborated": "review",
               "review_crit_eol_context": "review", "pass_clean": "pass"}

fig, ax = plt.subplots(figsize=(6.4, 4.2))

y_pos = np.arange(len(path_order))
counts = [path_counts.get(p, 0) for p in path_order]
colours = [TIER_COLOUR[path_tiers[p]] for p in path_order]
labels  = [PATH_LABELS[p] for p in path_order]

bars = ax.barh(y_pos, counts, height=0.55, color=colours, alpha=0.85,
               edgecolor="white", linewidth=0.5)
for i, (bar, c) in enumerate(zip(bars, counts)):
    ax.text(c + 0.05, i, str(c), va="center", fontsize=11, fontweight="bold")

ax.set_yticks(y_pos)
ax.set_yticklabels(labels, fontsize=10)
ax.set_xlim(0, max(counts) + 1.5)
ax.set_xlabel("Number of validation images", fontsize=10)
ax.set_xticks(range(max(counts) + 2))
ax.legend(handles=[
    mpatches.Patch(color=C_BLOCK,  alpha=0.85, label="BLOCK tier"),
    mpatches.Patch(color=C_REVIEW, alpha=0.85, label="REVIEW tier"),
    mpatches.Patch(color=C_PASS,   alpha=0.85, label="PASS tier"),
], loc="upper right", fontsize=9, frameon=False, ncol=2,
              bbox_to_anchor=(1.0, 1.10))
for spine in ["top", "right"]:
    ax.spines[spine].set_visible(False)

plt.tight_layout()
fig.savefig(os.path.join(OUT, "fig12_validation_gate_paths.png"),
            dpi=150, bbox_inches="tight")
fig.savefig(os.path.join(OUT, "fig12_validation_gate_paths.pdf"),
            dpi=150, bbox_inches="tight")
plt.close(fig)
print("  Saved fig12_validation_gate_paths.png")

print("Done.")
