import statistics,math
# PDF Table 5.5 values (as printed)
rows=[('web-dvwa',679,597,44004,45715),('juice-shop',467,353,41152,45526),('nginx:1.19',127,268,13473,14338),
('node:14',870,650,83038,77985),('python:3.8',949,1543,93746,96354),('alpine:3.19',7,182,6915,2498),
('nginx:1.29.7',154,386,14917,18047),('node:20',1045,877,98954,99559),('python:3.12',1056,861,92428,101863)]
print("ratio Grype/Trivy:")
for n,mb,t,g,o in rows: print(f"  {n:14} {g/t:7.1f}x   osv-vs-grype {(o-g)/g*100:+7.1f}%")
r=[g/t for n,mb,t,g,o in rows]
print(f"  range {min(r):.1f}x .. {max(r):.1f}x")
# alpine 182 vs 189
print("  alpine with n=30 trivy 189:", round(6915/189,1),"x")
print("node:20 vs alpine size ratio",1045/7, "time ratio",877/182, "(and 877/189=",round(877/189,1),")")
def lin(xs,ys):
    n=len(xs); mx=statistics.mean(xs); my=statistics.mean(ys)
    b=sum((x-mx)*(y-my) for x,y in zip(xs,ys))/sum((x-mx)**2 for x in xs)
    return b, my-b*mx
def pear(xs,ys):
    n=len(xs); mx=statistics.mean(xs); my=statistics.mean(ys)
    num=sum((x-mx)*(y-my) for x,y in zip(xs,ys))
    den=math.sqrt(sum((x-mx)**2 for x in xs)*sum((y-my)**2 for y in ys))
    r=num/den
    t=r*math.sqrt((n-2)/(1-r*r))
    return r,t
mb=[x[1] for x in rows]
for i,lab in ((2,'Trivy'),(3,'Grype'),(4,'OSV')):
    ys=[x[i] for x in rows]
    b,a=lin(mb,ys); r,t=pear(mb,ys)
    print(f"{lab:6} slope {b:7.2f} ms/MB  intercept {a:9.1f}  Pearson r={r:.4f}  t={t:.2f} df=7")
