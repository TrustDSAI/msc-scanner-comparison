import re,statistics,os
from collections import defaultdict
L=os.path.expanduser('~/msc-scanner-comparison/logs')
def parse(fn):
    r=[]
    for ln in open(fn):
        m=re.match(r'(\S+Z)\s+(\S+)\s+(\S+)\s+run(\d+)\s+(\d+)ms\s+([\d.]+)MB',ln)
        if m: r.append((m.group(1),m.group(2),m.group(3),int(m.group(4)),int(m.group(5)),float(m.group(6))))
    return r
b=[x for x in parse(f'{L}/benchmark.log') if x[0][:10]!='2026-04-04']
bt=parse(f'{L}/benchmark_trivy.log')
R=defaultdict(dict)
for ts,img,tool,run,ms,mb in b: R[(img,tool)][run]=ms
for ts,img,tool,run,ms,mb in bt: R[(img,'trivy30')][run]=ms
DESIGN=[('vulnerables_web-dvwa','web-dvwa'),('bkimminich_juice-shop','juice-shop'),('nginx_1.19','nginx:1.19'),
        ('node_14','node:14'),('python_3.8','python:3.8'),('alpine_3.19','alpine:3.19'),
        ('nginx_latest','nginx:1.29.7'),('node_20','node:20'),('python_3.12','python:3.12')]
PDF={'web-dvwa':(597,172,44004,2467,45715,1492),'juice-shop':(353,63,41152,2401,45526,4816),
 'nginx:1.19':(268,180,13473,2136,14338,1968),'node:14':(650,319,83038,4057,77985,4111),
 'python:3.8':(1543,360,93746,5417,96354,5535),'alpine:3.19':(182,25,6915,13911,2498,885),
 'nginx:1.29.7':(386,153,14917,1985,18047,2401),'node:20':(877,413,98954,4356,99559,9007),
 'python:3.12':(861,135,92428,5293,101863,9305)}
def ms(v): return (round(statistics.mean(v)), round(statistics.stdev(v)), len(v))
for safe,disp in DESIGN:
    t30=[R[(safe,'trivy30')][k] for k in sorted(R[(safe,'trivy30')])]
    g=[R[(safe,'grype')][k] for k in sorted(R[(safe,'grype')])]
    o=[R[(safe,'osv')][k] for k in sorted(R[(safe,'osv')])]
    p=PDF[disp]
    a=ms(t30); a2=ms(t30[1:])
    gg=ms(g); oo=ms(o)
    def mk(c,pm,ps): return "OK " if (c[0]==pm and c[1]==ps) else f"MISMATCH(pdf {pm}+-{ps})"
    print(f"{disp:14} trivy n30={a[0]}±{a[1]} n29={a2[0]}±{a2[1]} pdf={p[0]}±{p[1]} -> "
          f"{'n=30' if (a[0],a[1])==(p[0],p[1]) else ('n=29' if (a2[0],a2[1])==(p[0],p[1]) else 'NEITHER')}")
    print(f"{'':14} grype {gg[0]}±{gg[1]} (n={gg[2]}) pdf {p[2]}±{p[3]} {mk(gg,p[2],p[3])}   osv {oo[0]}±{oo[1]} (n={oo[2]}) pdf {p[4]}±{p[5]} {mk(oo,p[4],p[5])}")
