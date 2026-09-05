# figures_src — light-theme re-render of the p_gate CLI verdict figure

`render_cli_verdict_figure.py` redraws `p_gate-cli-verdict.png` (Figure 5.8) in a
light theme. The dark original used **Catppuccin Mocha**; this uses its official
light counterpart, **Catppuccin Latte**, so hue assignments (blue = CVE id,
yellow = section rule, red = decision, grey = provenance/dim) are unchanged.

The text is the same verdict output as the dark figure. It is not a fresh gate
run: re-running would refetch live EPSS/NVD/KEV and move the numbers the thesis
cites. The counts shown were re-verified against the stored data:

    python3 -c "
    import json, collections
    d = json.load(open('policy/output/vulnerables_web-dvwa_enriched_rule.json'))
    print(len(d['findings']),
          collections.Counter((x.get('severity') or '?').upper() for x in d['findings']))"
    # 2112 Counter({'HIGH': 760, 'MEDIUM': 702, 'CRITICAL': 328, 'LOW': 322})

matching the figure's `Total findings: 2112  Severity: CRITICAL 328 HIGH 760
MEDIUM 702 LOW 322`. The block/review split (31 / 742) is reproduced by
`analysis/ablation.py`.

## Run

    pip install playwright && python3 -m playwright install chromium
    python3 analysis/figures_src/render_cli_verdict_figure.py out.png

Fonts are embedded as `data:` URIs — Chromium blocks `file://` `@font-face`
loads, and the script asserts every face reached `loaded` rather than silently
falling back. JetBrains Mono (`fonts/`, from `@fontsource/jetbrains-mono`,
OFL-1.1) matches the original screenshot's face; its latin subset carries no
U+2500 box-drawing glyph, so DejaVu Sans Mono (shipped with matplotlib) stays in
the stack for the section rules.

Output is 2354x1680 at `device_scale_factor=2`, aspect 1.401 — the same aspect as
the 2340x1670 dark original, so the figure occupies the same space at
`width=\linewidth`.
