import sys; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
DESIGN = ['vulnerables_web-dvwa','bkimminich_juice-shop','nginx_1.19','node_14','python_3.8',
          'alpine_3.19','nginx_1.29.7','node_20','python_3.12']
ORD=['UNKNOWN','NEGLIGIBLE','LOW','MEDIUM','HIGH','CRITICAL']
tot_t=tot_g=tot_dis=0
print(f"{'image':22} {'shared':>7} {'agree%':>7} {'T_high':>7} {'G_high':>7} {'disag':>6}")
for img in DESIGN:
    ts=native(trivy_findings(img)); gs=native(grype_findings(img))
    shared=set(ts)&set(gs)
    ag=th=gh=0
    for c in shared:
        a,b=ts[c],gs[c]
        if a==b: ag+=1
        elif ORD.index(a)>ORD.index(b): th+=1
        else: gh+=1
    tot_t+=th; tot_g+=gh; tot_dis+=th+gh
    print(f"{img:22} {len(shared):7} {100*ag/len(shared):6.1f}% {th:7} {gh:7} {th+gh:6}")
print(f"TOTAL Trivy-higher {tot_t} Grype-higher {tot_g} disagreements {tot_dis}")
