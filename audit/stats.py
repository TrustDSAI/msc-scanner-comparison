"""Independent ecosystem split + Mann-Whitney, written from the dissertation prose."""
import sys,json,os,statistics; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
from scipy.stats import mannwhitneyu
DESIGN={"alpine_3.19","nginx_1.29.7","node_20","python_3.12","nginx_1.19","node_14",
        "python_3.8","vulnerables_web-dvwa","bkimminich_juice-shop"}
DISTRO={"deb","rpm","apk",""}
def measure(safe, root=RAW):
    tj=json.load(open(f'{root}/trivy/{safe}_trivy.json'))
    T=set(); lang=False
    for r in tj.get('Results') or []:
        vs=r.get('Vulnerabilities') or []
        for v in vs: T.add(v['VulnerabilityID'])
        if r.get('Class')=='lang-pkgs' and vs: lang=True
    gj=json.load(open(f'{root}/grype/{safe}_grype.json'))
    G=set()
    for m in gj['matches']:
        G.add(grype_canon(m))
        if (m.get('artifact') or {}).get('type','') not in DISTRO: lang=True
    j=len(T&G)/len(T|G) if T|G else 0.0
    return j, ('mixed' if lang else 'os')
rows=[(s,)+measure(s) for s in images()]
tr=[r for r in rows if r[0] in DESIGN]; ho=[r for r in rows if r[0] not in DESIGN]
def rep(name,rs):
    o=[r[1] for r in rs if r[2]=='os']; m=[r[1] for r in rs if r[2]=='mixed']
    u,p=mannwhitneyu(o,m,alternative='greater')
    u2,p2=mannwhitneyu(o,m,alternative='two-sided')
    print(f"{name}: n_os={len(o)} n_mixed={len(m)} mean_os={statistics.mean(o):.4f} mean_mixed={statistics.mean(m):.4f} "
          f"gap={statistics.mean(o)-statistics.mean(m):.4f}")
    print(f"   U={u} one-tailed p={p:.4f} | two-sided U={u2} p={p2:.4f}")
    print(f"   os images: {[ (r[0],round(r[1],3)) for r in rs if r[2]=='os']}")
    return o,m
o1,m1=rep("TRAINING (design 9)",tr)
o2,m2=rep("HELD-OUT (21)",ho)
o3,m3=rep("ALL 30",rows)
# Cohen's d on training
import math
def cohend(a,b):
    na,nb=len(a),len(b); sa,sb=statistics.variance(a),statistics.variance(b)
    sp=math.sqrt(((na-1)*sa+(nb-1)*sb)/(na+nb-2))
    return (statistics.mean(a)-statistics.mean(b))/sp
print(f"\nCohen's d (training) = {cohend(o1,m1):.4f}")
