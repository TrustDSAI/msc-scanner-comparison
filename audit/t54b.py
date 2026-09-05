import sys; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
DESIGN = ['vulnerables_web-dvwa','bkimminich_juice-shop','nginx_1.19','node_14','python_3.8',
          'alpine_3.19','nginx_1.29.7','node_20','python_3.12']
RANK={'UNKNOWN':0,'NEGLIGIBLE':1,'LOW':2,'MEDIUM':3,'HIGH':4,'CRITICAL':5}
def lastwins(fs,key='id'):
    d={}
    for f in fs: d[f[key]]=f['sev']
    return d
tt=gg=0
print(f"{'image':22} {'shared':>7} {'agree%':>7} {'T_high':>7} {'G_high':>7}")
for img in DESIGN:
    ts=lastwins(trivy_findings(img)); gs=lastwins(grype_findings(img))
    shared=set(ts)&set(gs); ag=th=gh=0
    for c in shared:
        if ts[c]==gs[c]: ag+=1
        elif RANK.get(ts[c],0)>RANK.get(gs[c],0): th+=1
        else: gh+=1
    tt+=th; gg+=gh
    print(f"{img:22} {len(shared):7} {100*ag/len(shared):6.1f}% {th:7} {gh:7}")
print("TOTAL T-higher",tt,"G-higher",gg,"disagreements",tt+gg)
