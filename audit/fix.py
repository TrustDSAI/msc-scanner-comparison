import sys; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
DESIGN = ['vulnerables_web-dvwa','bkimminich_juice-shop','nginx_1.19','node_14','python_3.8',
          'alpine_3.19','nginx_1.29.7','node_20','python_3.12']
print(f"{'image':22} | raw-record basis      | native unique-CVE basis")
print(f"{'':22} | {'T%':>6} {'G%':>6} {'Tn':>5} {'Gn':>5} | {'T%':>6} {'G%':>6} {'Tn':>5} {'Gn':>5}")
for img in DESIGN:
    tf=trivy_findings(img); gf=grype_findings(img)
    tr=100*sum(f['fixed'] for f in tf)/len(tf); gr=100*sum(f['fixed'] for f in gf)/len(gf)
    # native: CVE counted fixed if any record has a fix
    tu={}; gu={}
    for f in tf: tu[f['id']]=tu.get(f['id'],False) or f['fixed']
    for f in gf: gu[f['id']]=gu.get(f['id'],False) or f['fixed']
    tn=100*sum(tu.values())/len(tu); gn=100*sum(gu.values())/len(gu)
    print(f"{img:22} | {tr:6.1f} {gr:6.1f} {len(tf):5} {len(gf):5} | {tn:6.1f} {gn:6.1f} {len(tu):5} {len(gu):5}")
