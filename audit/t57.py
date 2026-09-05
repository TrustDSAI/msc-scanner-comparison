import csv,os
p=os.path.expanduser('~/msc-scanner-comparison/policy/output/verdict_matrix.csv')
r=list(csv.DictReader(open(p)))
idx={(x['image'],x['classifier'],x['policy']):x for x in r}
imgs=[]
for x in r:
    if x['image'] not in imgs: imgs.append(x['image'])
print("agent P5 web-dvwa:", idx[('vulnerables/web-dvwa','agent','P5_layer')]['deny_count'],
      " agent P4_relaxed:", idx[('vulnerables/web-dvwa','agent','P4_relaxed')]['deny_count'])
print("agent P5 juice-shop:", idx[('bkimminich/juice-shop','agent','P5_layer')]['deny_count'])
tot=0; blocks=0
print(f"\n{'image':26} {'critTot':>8} {'p_gate_BR':>10} {'block?':>7}")
for im in imgs:
    g=idx[(im,'rule','p_gate')]
    ct=idx[(im,'rule','P1')]['critical_total']
    tot+=int(g['deny_count'])
    blocks+= (g['block']=='True')
    print(f"{im:26} {ct:>8} {g['deny_count']:>10} {g['block']:>7}")
print(f"\nSUM Block+Review = {tot}   images with block=True = {blocks}")
# P1 blocks (merged) and native baselines
p1b=[im for im in imgs if idx[(im,'rule','P1')]['block']=='True']
print(f"P1 (merged any-CRITICAL) blocks {len(p1b)} images")
