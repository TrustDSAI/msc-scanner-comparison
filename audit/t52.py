import sys; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
DESIGN = ['vulnerables_web-dvwa','bkimminich_juice-shop','nginx_1.19','node_14','python_3.8',
          'alpine_3.19','nginx_1.29.7','node_20','python_3.12']
print(f"{'image':22} {'T':>5} {'G_alias':>7} {'G_raw':>6} {'Tonly':>6} {'Both':>5} {'Gonly':>6} {'J_alias':>8} {'J_raw':>7} {'delta':>7}")
for img in DESIGN:
    T = set(f['id'] for f in trivy_findings(img))
    gf = grype_findings(img)
    Ga = set(f['id'] for f in gf); Gr = set(f['raw'] for f in gf)
    both = T & Ga
    ja = len(both)/len(T|Ga)
    jr = len(T & Gr)/len(T | Gr)
    print(f"{img:22} {len(T):5} {len(Ga):7} {len(Gr):6} {len(T-Ga):6} {len(both):5} {len(Ga-T):6} {ja:8.3f} {jr:7.3f} {abs(ja-jr):7.3f}")
