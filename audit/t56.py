import csv,os
p=os.path.expanduser('~/msc-scanner-comparison/policy/output/verdict_matrix.csv')
r=list(csv.DictReader(open(p)))
pols=sorted({x['policy'] for x in r})
print("policies:",pols)
print("classifiers:",sorted({x['classifier'] for x in r}))
imgs=[]
for x in r:
    if x['image'] not in imgs: imgs.append(x['image'])
print("images:",len(imgs))
D=['vulnerables/web-dvwa','bkimminich/juice-shop','nginx:1.19','node:14','python:3.8','alpine:3.19','nginx:1.29.7','node:20','python:3.12']
idx={(x['image'],x['classifier'],x['policy']):x for x in r}
cols=['P1','P2','P3','P4_strict','P4_relaxed','P5_layer','P7_severity_aware','p_gate']
print(f"{'image':24} {'critTot':>8} "+" ".join(f"{c:>12}" for c in cols))
for im in D:
    row=[]
    ct=idx.get((im,'rule','P1'),{}).get('critical_total','-')
    for c in cols:
        k=idx.get((im,'rule',c))
        row.append(k['deny_count'] if k else '--')
    print(f"{im:24} {ct:>8} "+" ".join(f"{v:>12}" for v in row))
