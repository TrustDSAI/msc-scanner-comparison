import sys,json,os,collections; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
DESIGN = ['vulnerables_web-dvwa','bkimminich_juice-shop','nginx_1.19','node_14','python_3.8',
          'alpine_3.19','nginx_1.29.7','node_20','python_3.12']
def variants(dedup):
    T=collections.Counter(); G=collections.Counter()
    for img in DESIGN:
        d=json.load(open(f'{RAW}/trivy/{img}_trivy.json'))
        seen={}
        for r in d.get('Results') or []:
            for v in r.get('Vulnerabilities') or []:
                cw=v.get('CweIDs') or []
                if dedup: seen[v['VulnerabilityID']]=cw
                else: T.update(cw)
        if dedup:
            for cw in seen.values(): T.update(cw)
        g=json.load(open(f'{RAW}/grype/{img}_grype.json'))
        seen={}
        for m in g['matches']:
            v=m['vulnerability']
            cw=[c.get('cwe','') for c in (v.get('cwes') or []) if c.get('cwe')]
            if dedup: seen[v['id']]=cw
            else: G.update(cw)
        if dedup:
            for cw in seen.values(): G.update(cw)
    return T,G
for dedup in (True,False):
    T,G=variants(dedup)
    tot=T+G
    print("=== dedup-by-CVE" if dedup else "=== all records")
    for c,n in tot.most_common(6):
        print(f"  {c:10} sum={n:5}  T={T[c]:5} G={G[c]:5}")
    print("  T>G on", sum(1 for c,_ in tot.most_common(20) if T[c]>G[c]), "of 20; G>T on", sum(1 for c,_ in tot.most_common(20) if G[c]>T[c]))
