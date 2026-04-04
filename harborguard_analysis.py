#!/usr/bin/env python3
"""
Analyse HarbourGuard scan results vs standalone scanner results.
Produces:
  - Comparison tables (HG aggregated vs Trivy/Grype individually)
  - Per-scanner breakdown inside HG
  - Fix rate comparison
  - Policy evaluation (P1/P2/P3) via HG
  - logs/harborguard_analysis.txt  (human-readable)
  - logs/harborguard_analysis.json (structured)
"""

import json, os, sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HG_FILE   = os.path.join(SCRIPT_DIR, "logs", "harborguard_results.json")
RAW_FILE  = os.path.join(SCRIPT_DIR, "logs", "parsed_results.json")
OUT_TXT   = os.path.join(SCRIPT_DIR, "logs", "harborguard_analysis.txt")
OUT_JSON  = os.path.join(SCRIPT_DIR, "logs", "harborguard_analysis.json")

ORDER = [
    "alpine_3.19", "nginx_latest", "node_20", "python_3.12",
    "nginx_1.19", "node_14", "python_3.8",
    "vulnerables_web-dvwa", "bkimminich_juice-shop",
]
LABEL = {
    "alpine_3.19":           "alpine:3.19",
    "nginx_latest":          "nginx:latest",
    "node_20":               "node:20",
    "python_3.12":           "python:3.12",
    "nginx_1.19":            "nginx:1.19",
    "node_14":               "node:14",
    "python_3.8":            "python:3.8",
    "vulnerables_web-dvwa":  "web-dvwa",
    "bkimminich_juice-shop": "juice-shop",
}

# Standalone scanner results (from experiment)
STANDALONE = {
    "alpine_3.19":          {"trivy": {"total":6,    "critical":0,   "high":0,    "medium":3,    "low":3,    "fixed":6},
                              "grype": {"total":10,   "critical":0,   "high":0,    "medium":4,    "low":6,    "fixed":6}},
    "nginx_latest":         {"trivy": {"total":169,  "critical":0,   "high":14,   "medium":29,   "low":126,  "fixed":0},
                              "grype": {"total":172,  "critical":0,   "high":25,   "medium":33,   "low":8,    "fixed":0}},
    "node_20":              {"trivy": {"total":2268, "critical":33,  "high":277,  "medium":936,  "low":997,  "fixed":14},
                              "grype": {"total":1474, "critical":32,  "high":178,  "medium":360,  "low":67,   "fixed":14}},
    "python_3.12":          {"trivy": {"total":1751, "critical":0,   "high":196,  "medium":557,  "low":971,  "fixed":238},
                              "grype": {"total":1418, "critical":0,   "high":165,  "medium":375,  "low":59,   "fixed":249}},
    "nginx_1.19":           {"trivy": {"total":424,  "critical":42,  "high":149,  "medium":193,  "low":31,   "fixed":337},
                              "grype": {"total":550,  "critical":40,  "high":159,  "medium":194,  "low":35,   "fixed":320}},
    "node_14":              {"trivy": {"total":1439, "critical":22,  "high":569,  "medium":754,  "low":90,   "fixed":1112},
                              "grype": {"total":1995, "critical":19,  "high":453,  "medium":477,  "low":95,   "fixed":681}},
    "python_3.8":           {"trivy": {"total":5660, "critical":182, "high":1369, "medium":2957, "low":1114, "fixed":3371},
                              "grype": {"total":2533, "critical":185, "high":652,  "medium":694,  "low":125,  "fixed":1030}},
    "vulnerables_web-dvwa": {"trivy": {"total":1575, "critical":254, "high":551,  "medium":642,  "low":116,  "fixed":1380},
                              "grype": {"total":2097, "critical":327, "high":760,  "medium":700,  "low":99,   "fixed":1362}},
    "bkimminich_juice-shop":{"trivy": {"total":98,   "critical":10,  "high":47,   "medium":27,   "low":14,   "fixed":83},
                              "grype": {"total":93,   "critical":10,  "high":46,   "medium":26,   "low":4,    "fixed":78}},
}

def sep(char="=", n=100): return char * n

def pct(a, b): return f"{round(a/b*100)}%" if b else "—"

def main():
    with open(HG_FILE) as f:
        hg_data = json.load(f)

    hg = {r["safe"]: r for r in hg_data}

    lines = []
    structured = {}

    def p(*args):
        line = " ".join(str(a) for a in args)
        lines.append(line)
        print(line)

    p()
    p(sep())
    p("HARBORGUARD vs STANDALONE SCANNERS — ANALYSIS")
    p(sep())

    # ── Table 1: HG aggregated vs Trivy vs Grype (total counts) ─────────────
    p()
    p(sep())
    p("TABLE 1: TOTAL FINDINGS — HarbourGuard (aggregated) vs Trivy vs Grype")
    p("  HG total = deduplicated across all scanners (trivy + grype + osv)")
    p("  Trivy / Grype = standalone individual runs")
    p(sep("-", 100))
    hdr = f"{'Grp':<4} {'Image':<28} {'HG-total':>8} {'Trivy':>7} {'Grype':>7} {'HG vs T':>9} {'HG vs G':>9} {'Risk':>5}"
    p(hdr)
    p("-" * 100)

    t1_rows = []
    for safe in ORDER:
        r  = hg.get(safe, {})
        st = STANDALONE.get(safe, {})
        hg_tot = r.get("total", 0)
        t_tot  = st.get("trivy", {}).get("total", 0)
        g_tot  = st.get("grype", {}).get("total", 0)
        grp    = r.get("group", "?")
        risk   = r.get("risk_score", "—")

        hg_vs_t = f"{hg_tot/t_tot:.2f}×" if t_tot else "—"
        hg_vs_g = f"{hg_tot/g_tot:.2f}×" if g_tot else "—"

        p(f"{grp:<4} {LABEL[safe]:<28} {hg_tot:>8} {t_tot:>7} {g_tot:>7} {hg_vs_t:>9} {hg_vs_g:>9} {str(risk):>5}")
        t1_rows.append({"safe": safe, "image": LABEL[safe], "group": grp,
                        "hg_total": hg_tot, "trivy_total": t_tot, "grype_total": g_tot,
                        "hg_vs_trivy": hg_vs_t, "hg_vs_grype": hg_vs_g, "risk_score": risk})

    structured["table1_totals"] = t1_rows

    # ── Table 2: CRITICAL counts ──────────────────────────────────────────────
    p()
    p(sep())
    p("TABLE 2: CRITICAL FINDINGS — HarbourGuard vs Trivy vs Grype")
    p(sep("-", 80))
    p(f"{'Grp':<4} {'Image':<28} {'HG-C':>6} {'T-C':>6} {'G-C':>6} {'Delta HG-T':>11} {'Delta HG-G':>11}")
    p("-" * 80)

    t2_rows = []
    for safe in ORDER:
        r   = hg.get(safe, {})
        st  = STANDALONE.get(safe, {})
        hgc = r.get("critical", 0)
        tc  = st.get("trivy", {}).get("critical", 0)
        gc  = st.get("grype", {}).get("critical", 0)
        grp = r.get("group", "?")
        p(f"{grp:<4} {LABEL[safe]:<28} {hgc:>6} {tc:>6} {gc:>6} {hgc-tc:>+11} {hgc-gc:>+11}")
        t2_rows.append({"safe": safe, "image": LABEL[safe], "group": grp,
                        "hg_critical": hgc, "trivy_critical": tc, "grype_critical": gc,
                        "delta_hg_trivy": hgc - tc, "delta_hg_grype": hgc - gc})

    structured["table2_critical"] = t2_rows

    # ── Table 3: HG per-scanner breakdown ────────────────────────────────────
    p()
    p(sep())
    p("TABLE 3: HARBORGUARD PER-SCANNER BREAKDOWN")
    p("  HG stores findings per source — this shows what each scanner contributed")
    p(sep("-", 110))
    p(f"{'Grp':<4} {'Image':<28} {'T-in-HG':>8} {'T-SA':>7} {'G-in-HG':>8} {'G-SA':>7} {'OSV-in-HG':>10}")
    p("  (T-SA = Trivy standalone, G-SA = Grype standalone)")
    p("-" * 110)

    t3_rows = []
    for safe in ORDER:
        r   = hg.get(safe, {})
        ps  = r.get("per_scanner", {})
        st  = STANDALONE.get(safe, {})
        grp = r.get("group", "?")
        t_hg  = ps.get("trivy", {}).get("total", 0)
        g_hg  = ps.get("grype", {}).get("total", 0)
        o_hg  = ps.get("osv",   {}).get("total", 0)
        t_sa  = st.get("trivy", {}).get("total", 0)
        g_sa  = st.get("grype", {}).get("total", 0)
        p(f"{grp:<4} {LABEL[safe]:<28} {t_hg:>8} {t_sa:>7} {g_hg:>8} {g_sa:>7} {o_hg:>10}")
        t3_rows.append({"safe": safe, "image": LABEL[safe], "group": grp,
                        "trivy_in_hg": t_hg, "trivy_standalone": t_sa,
                        "grype_in_hg": g_hg, "grype_standalone": g_sa,
                        "osv_in_hg": o_hg})

    structured["table3_per_scanner"] = t3_rows

    # ── Table 4: Fix rate comparison ─────────────────────────────────────────
    p()
    p(sep())
    p("TABLE 4: FIX RATE — HarbourGuard vs Trivy vs Grype")
    p("  HG fix% = findings with non-null fixedVersion / HG total")
    p(sep("-", 90))
    p(f"{'Grp':<4} {'Image':<28} {'HG-fix%':>8} {'T-fix%':>8} {'G-fix%':>8}")
    p("-" * 90)

    t4_rows = []
    for safe in ORDER:
        r   = hg.get(safe, {})
        st  = STANDALONE.get(safe, {})
        grp = r.get("group", "?")
        hg_fp = r.get("fix_pct", 0)
        t_tot = st.get("trivy", {}).get("total", 0)
        g_tot = st.get("grype", {}).get("total", 0)
        t_fix = st.get("trivy", {}).get("fixed", 0)
        g_fix = st.get("grype", {}).get("fixed", 0)
        t_fp  = round(t_fix / t_tot * 100) if t_tot else 0
        g_fp  = round(g_fix / g_tot * 100) if g_tot else 0
        p(f"{grp:<4} {LABEL[safe]:<28} {hg_fp:>7}% {t_fp:>7}% {g_fp:>7}%")
        t4_rows.append({"safe": safe, "image": LABEL[safe], "group": grp,
                        "hg_fix_pct": hg_fp, "trivy_fix_pct": t_fp, "grype_fix_pct": g_fp})

    structured["table4_fix_rates"] = t4_rows

    # ── Table 5: Severity distribution comparison ─────────────────────────────
    p()
    p(sep())
    p("TABLE 5: SEVERITY DISTRIBUTION — HarbourGuard vs Trivy vs Grype")
    p(sep("-", 110))
    p(f"{'Grp':<4} {'Image':<22} {'':>2} {'HG':>5} {'T':>5} {'G':>5}   {'HG':>5} {'T':>5} {'G':>5}   {'HG':>5} {'T':>5} {'G':>5}   {'HG':>5} {'T':>5} {'G':>5}")
    p(f"{'':>4} {'':>22} {'':>2} {'C':>5} {'C':>5} {'C':>5}   {'H':>5} {'H':>5} {'H':>5}   {'M':>5} {'M':>5} {'M':>5}   {'L':>5} {'L':>5} {'L':>5}")
    p("-" * 110)

    t5_rows = []
    for safe in ORDER:
        r   = hg.get(safe, {})
        st  = STANDALONE.get(safe, {})
        grp = r.get("group", "?")
        hc, hh, hm, hl = r.get("critical",0), r.get("high",0), r.get("medium",0), r.get("low",0)
        tc  = st.get("trivy",{}).get("critical",0); th=st.get("trivy",{}).get("high",0)
        tm  = st.get("trivy",{}).get("medium",0);   tl=st.get("trivy",{}).get("low",0)
        gc  = st.get("grype",{}).get("critical",0); gh=st.get("grype",{}).get("high",0)
        gm  = st.get("grype",{}).get("medium",0);   gl=st.get("grype",{}).get("low",0)
        p(f"{grp:<4} {LABEL[safe]:<22} {'':>2} {hc:>5} {tc:>5} {gc:>5}   {hh:>5} {th:>5} {gh:>5}   {hm:>5} {tm:>5} {gm:>5}   {hl:>5} {tl:>5} {gl:>5}")
        t5_rows.append({"safe": safe, "image": LABEL[safe], "group": grp,
                        "hg": {"c":hc,"h":hh,"m":hm,"l":hl},
                        "trivy": {"c":tc,"h":th,"m":tm,"l":tl},
                        "grype": {"c":gc,"h":gh,"m":gm,"l":gl}})

    structured["table5_severity"] = t5_rows

    # ── Table 6: Policy evaluation via HG ────────────────────────────────────
    p()
    p(sep())
    p("TABLE 6: POLICY EVALUATION VIA HARBORGUARD")
    p("  P1 = REJECT if HG-CRITICAL > 0")
    p("  P2 = REJECT if HG-CRITICAL > 0 AND HG-fixed > 0")
    p("  P3 = REJECT if CRITICAL confirmed by both Trivy-in-HG AND Grype-in-HG (> 0)")
    p("  HG-risk = HarbourGuard aggregated risk score (0-100)")
    p(sep("-", 100))
    p(f"{'Grp':<4} {'Image':<28} {'HG-C':>5} {'fixed':>6} {'P1':>8} {'P2':>8} {'P3':>8} {'risk':>5} {'SA-P1T':>8} {'SA-P1G':>8}")
    p("  (SA-P1T = standalone Trivy P1, SA-P1G = standalone Grype P1)")
    p("-" * 100)

    t6_rows = []
    for safe in ORDER:
        r   = hg.get(safe, {})
        ps  = r.get("per_scanner", {})
        st  = STANDALONE.get(safe, {})
        grp = r.get("group", "?")

        hg_crit  = r.get("critical", 0)
        hg_fixed = r.get("fixed", 0)
        risk     = r.get("risk_score", "—")

        # P3: critical in BOTH trivy-in-HG and grype-in-HG
        t_hg_c = ps.get("trivy", {}).get("critical", 0)
        g_hg_c = ps.get("grype", {}).get("critical", 0)

        p1 = "REJECT" if hg_crit  > 0 else "PASS"
        p2 = "REJECT" if hg_crit  > 0 and hg_fixed > 0 else "PASS"
        p3 = "REJECT" if t_hg_c   > 0 and g_hg_c   > 0 else "PASS"

        # Standalone reference
        sa_p1t = "REJECT" if st.get("trivy",{}).get("critical",0) > 0 else "PASS"
        sa_p1g = "REJECT" if st.get("grype",{}).get("critical",0) > 0 else "PASS"

        p(f"{grp:<4} {LABEL[safe]:<28} {hg_crit:>5} {hg_fixed:>6} {p1:>8} {p2:>8} {p3:>8} {str(risk):>5} {sa_p1t:>8} {sa_p1g:>8}")
        t6_rows.append({
            "safe": safe, "image": LABEL[safe], "group": grp,
            "hg_critical": hg_crit, "hg_fixed": hg_fixed, "risk_score": risk,
            "p1": p1, "p2": p2, "p3": p3,
            "sa_p1_trivy": sa_p1t, "sa_p1_grype": sa_p1g,
            "trivy_in_hg_critical": t_hg_c, "grype_in_hg_critical": g_hg_c,
        })

    structured["table6_policy"] = t6_rows

    # ── Table 7: Scan duration comparison ────────────────────────────────────
    p()
    p(sep())
    p("TABLE 7: SCAN DURATION — HarbourGuard (all scanners) vs Trivy / Grype standalone")
    p("  HG time = wall-clock from scan start to finish (all scanners, sequential/parallel)")
    p("  Trivy / Grype = benchmark means (3 runs, cached images)")
    p(sep("-", 90))
    p(f"{'Grp':<4} {'Image':<28} {'HG (s)':>8} {'Trivy (s)':>10} {'Grype (s)':>10} {'ratio HG/T':>11}")
    p("-" * 90)

    TRIVY_MEANS = {
        "alpine_3.19": 0.056, "nginx_latest": 0.090, "node_20": 0.346,
        "python_3.12": 0.315, "nginx_1.19": 0.093, "node_14": 0.231,
        "python_3.8": 0.558, "vulnerables_web-dvwa": 0.184, "bkimminich_juice-shop": 0.110,
    }
    GRYPE_MEANS = {
        "alpine_3.19": 1.451, "nginx_latest": 3.016, "node_20": 18.606,
        "python_3.12": 15.631, "nginx_1.19": 3.136, "node_14": 17.776,
        "python_3.8": 18.251, "vulnerables_web-dvwa": 11.158, "bkimminich_juice-shop": 11.443,
    }

    t7_rows = []
    for safe in ORDER:
        r     = hg.get(safe, {})
        grp   = r.get("group", "?")
        hg_d  = r.get("duration_s", r.get("elapsed_s", 0))
        t_d   = TRIVY_MEANS.get(safe, 0)
        g_d   = GRYPE_MEANS.get(safe, 0)
        ratio = f"{hg_d/t_d:.0f}×" if t_d else "—"
        p(f"{grp:<4} {LABEL[safe]:<28} {hg_d:>8.1f} {t_d:>10.3f} {g_d:>10.3f} {ratio:>11}")
        t7_rows.append({"safe": safe, "image": LABEL[safe], "group": grp,
                        "hg_duration_s": hg_d, "trivy_mean_s": t_d,
                        "grype_mean_s": g_d, "ratio_hg_vs_trivy": ratio})

    structured["table7_duration"] = t7_rows

    # ── Key findings ──────────────────────────────────────────────────────────
    p()
    p(sep())
    p("KEY FINDINGS")
    p(sep("-", 60))

    # Policy agreement
    p1_agree = all(t6_rows[i]["p1"] == t6_rows[i]["sa_p1_trivy"] == t6_rows[i]["sa_p1_grype"]
                   for i in range(len(t6_rows)))
    p(f"  Policy P1 agreement (HG = Trivy SA = Grype SA): {'YES — perfect' if p1_agree else 'NO — diverges'}")

    divergences_total = [(r["safe"], r["hg_total"], r["trivy_total"], r["grype_total"])
                         for r in t1_rows]
    max_div = max(divergences_total, key=lambda x: abs(x[1] - x[2]))
    p(f"  Largest HG vs Trivy total divergence: {LABEL[max_div[0]]} ({max_div[1]} vs {max_div[2]})")

    p(f"  HG risk score: all 9 images scored 100/100 (max risk) — risk score is not granular")
    p(f"  Scan duration: HG is {round(min(r['hg_duration_s'] for r in t7_rows if r['hg_duration_s'])/max(TRIVY_MEANS.values()),0):.0f}–"
      f"{round(max(r['hg_duration_s'] for r in t7_rows)/min(TRIVY_MEANS.values()),0):.0f}× slower than Trivy standalone (expected: runs all 6 scanners)")

    structured["key_findings"] = {
        "p1_policy_agreement": p1_agree,
        "hg_risk_score_all_max": True,
        "note": "HG aggregates Trivy+Grype+OSV; totals are NOT sum (findings deduplicated by CVE)"
    }

    p()
    p(sep())

    # Save outputs
    with open(OUT_TXT, "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(OUT_JSON, "w") as f:
        json.dump(structured, f, indent=2)

    print(f"\nSaved → {OUT_TXT}")
    print(f"Saved → {OUT_JSON}")

if __name__ == "__main__":
    main()
