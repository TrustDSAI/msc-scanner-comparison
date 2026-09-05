import sys; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
rows=[]
for img in images():
    ts=native(trivy_findings(img)); gs=native(grype_findings(img))
    tc=sum(1 for v in ts.values() if v=='CRITICAL'); gc=sum(1 for v in gs.values() if v=='CRITICAL')
    rows.append((img,tc,gc,abs(tc-gc)))
viol=[r for r in rows if r[3]>3]
print("violations (delta>3):",len(viol),"of",len(rows))
for r in sorted(viol,key=lambda x:-x[3]): print(f"  {r[0]:24} T={r[1]:4} G={r[2]:4} d={r[3]}")
print("holds on",len(rows)-len(viol),"of",len(rows))
