import sys,collections; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
IMGS=['node_14','node_20','python_3.8','python_3.12']
print("--- linux-libc-dev share of Trivy-only CVEs")
for img in IMGS:
    tf=trivy_findings(img); gf=grype_findings(img)
    T=set(f['id'] for f in tf); G=set(f['id'] for f in gf)
    tonly=T-G
    llc=set(f['id'] for f in tf if f['pkg']=='linux-libc-dev')
    n=len(tonly & llc)
    print(f"  {img:12} trivy-only={len(tonly):5}  from linux-libc-dev={n:5}  {100*n/len(tonly):5.1f}%")
    gp={f['pkg'] for f in gf}
    print(f"               linux-libc-dev in Grype inventory: {'linux-libc-dev' in gp}")
print("\n--- python:3.8 Trivy total without linux-libc-dev")
tf=trivy_findings('python_3.8')
T=set(f['id'] for f in tf)
noll=set(f['id'] for f in tf if f['pkg']!='linux-libc-dev')
print(f"  total={len(T)}  excluding CVEs *only* from linux-libc-dev = {len(noll)}")
print("\n--- GHSA namespace counts (Grype)")
for img in IMGS+['bkimminich_juice-shop']:
    gf=grype_findings(img)
    gh=[f for f in gf if 'github' in (f['ns'] or '')]
    ns=collections.Counter(f['ns'] for f in gf)
    print(f"  {img:22} total_matches={len(gf):5} ghsa_ns={len(gh):4}  namespaces={dict(ns)}")
