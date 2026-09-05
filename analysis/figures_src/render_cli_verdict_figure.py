# Re-render the policy_gate.py CLI verdict figure in a light theme.
# Text is the same output as the existing dark figure; the counts in it were
# re-verified against policy/output/vulnerables_web-dvwa_enriched_rule.json
# (2112 findings; CRITICAL 328 / HIGH 760 / MEDIUM 702 / LOW 322) and against
# the gate re-run (block 31, review 742).
# Palette: Catppuccin Mocha (the original) -> Catppuccin Latte (this one).
import base64, html, pathlib, sys
from playwright.sync_api import sync_playwright

MPL = "/usr/local/lib64/python3.9/site-packages/matplotlib/mpl-data/fonts/ttf"
FONT, FONT_B = f"{MPL}/DejaVuSansMono.ttf", f"{MPL}/DejaVuSansMono-Bold.ttf"
# JetBrains Mono matches the original screenshot's face; its latin subset has no
# box-drawing glyphs, so DejaVu Sans Mono stays in the stack for U+2500.
JB = pathlib.Path(__file__).parent / "fonts"
JBM = JB / "jetbrains-mono-latin-400-normal.woff2"
JBM_B = JB / "jetbrains-mono-latin-700-normal.woff2"

def data_uri(path, mime):
    return f"data:{mime};base64," + base64.b64encode(pathlib.Path(path).read_bytes()).decode()

U_JBM, U_JBM_B = data_uri(JBM, "font/woff2"), data_uri(JBM_B, "font/woff2")
U_DJM, U_DJM_B = data_uri(FONT, "font/ttf"), data_uri(FONT_B, "font/ttf")

# Latte
BG, TXT, DIM, RED, YEL, BLU = "#eff1f5", "#4c4f69", "#6c6f85", "#d20f39", "#df8e1d", "#1e66f5"

def sp(cls, s):  # coloured span
    return f'<span class="{cls}">{html.escape(s)}</span>'

def row(cve, pkg, epss, kev, reason):
    return (sp("blu", f"{cve:<18}") + html.escape(f"{pkg:<24}{epss:<7}{kev:<5}") + html.escape(reason))

RULE_END = 76
def rule(label):
    dashes = "─" * max(0, RULE_END - len(label) - 1)
    return sp("yel b", label) + " " + sp("yel", dashes)

HDR = sp("dim", f"{'CVE':<18}{'Package':<24}{'EPSS':<7}{'KEV':<5}Reason")

BLOCK = [("CVE-2021-40438", "apache2", "0.944", "yes"),
         ("CVE-2021-40438", "apache2-bin", "0.944", "yes"),
         ("CVE-2021-40438", "apache2-data", "0.944", "yes"),
         ("CVE-2021-40438", "apache2-utils", "0.944", "yes"),
         ("CVE-2019-11043", "libapache2-mod-php7.0", "0.941", "yes"),
         ("CVE-2019-11043", "php7.0", "0.941", "yes")]
REVIEW = [("CVE-2018-19518", p, "0.940", "-") for p in
          ("libapache2-mod-php7.0", "php7.0", "php7.0-cli",
           "php7.0-common", "php7.0-gd", "php7.0-json")]

L = []
L.append(html.escape("$ policy_gate.py --image vulnerables/web-dvwa:latest \\"))
L.append(html.escape("      --trivy trivy.json --grype grype.json --report-format markdown"))
L.append("")
L.append(sp("b", "# Vulnerability gate report: vulnerables/web-dvwa:latest"))
L.append("")
L.append(sp("red b", "Decision: BLOCK") + html.escape("   (block: 31, review: 742, suppressed: 0)"))
L.append(html.escape("Image is end-of-life  (source: trivy:os-eosl)"))
L.append(sp("dim", "Provenance: trivy 0.69.3, grype 0.110.0, opa 1.17.0, classifier=rule"))
L.append(sp("dim", "Scanned: 2026-06-21"))
L.append("")
L.append(html.escape("Total findings: 2112   Severity: CRITICAL 328 HIGH 760 MEDIUM 702 LOW 322"))
L.append("")
L.append(rule("— Block (31) — top 6 by EPSS"))
L.append(HDR)
for c, p, e, k in BLOCK:
    L.append(row(c, p, e, k, "KEV catalog: actively exploited, fix available"))
L.append(sp("dim", "… 25 more block findings"))
L.append("")
L.append(rule("— Review (742) — top 6 by EPSS"))
L.append(HDR)
for c, p, e, k in REVIEW:
    L.append(row(c, p, e, k, "HIGH with fix and consensus, needs human decision"))
L.append(sp("dim", "… 736 more review findings"))

DOC = f"""<!doctype html><meta charset=utf-8><style>
@font-face {{ font-family: JBM; src: url({U_JBM}) format('woff2'); font-weight: 400; }}
@font-face {{ font-family: JBM; src: url({U_JBM_B}) format('woff2'); font-weight: 700; }}
@font-face {{ font-family: DJM; src: url({U_DJM}) format('truetype'); font-weight: 400; }}
@font-face {{ font-family: DJM; src: url({U_DJM_B}) format('truetype'); font-weight: 700; }}
html,body {{ margin:0; padding:0; background:{BG}; }}
#t {{ display:inline-block; background:{BG}; color:{TXT};
     font-family: JBM, DJM, monospace; font-size:18.4px; line-height:25.65px;
     padding:22px 22px; white-space:pre; }}
.b {{ font-weight:700; }} .dim {{ color:{DIM}; }} .red {{ color:{RED}; }}
.yel {{ color:{YEL}; }} .blu {{ color:{BLU}; }}
</style><div id=t>{chr(10).join(L)}</div>"""

out = pathlib.Path(sys.argv[1])
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-sandbox", "--force-color-profile=srgb"])
    pg = b.new_page(device_scale_factor=2)
    pg.set_content(DOC)
    pg.evaluate("document.fonts.ready")
    pg.wait_for_timeout(500)
    bad = pg.evaluate("Array.from(document.fonts).filter(f=>f.status!=='loaded').map(f=>f.family)")
    assert not bad, f"font(s) failed to load: {bad}"
    pg.locator("#t").screenshot(path=str(out))
    b.close()
from PIL import Image
im = Image.open(out)
print("wrote", out, im.size, "aspect", round(im.size[0]/im.size[1], 3))
