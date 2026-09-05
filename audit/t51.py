import sys; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
DESIGN = ['vulnerables_web-dvwa','bkimminich_juice-shop','nginx_1.19','node_14','python_3.8',
          'alpine_3.19','nginx_1.29.7','node_20','python_3.12']
print(f"{'image':24} {'T_tot':>6}{'T_CRIT':>7}{'T_HIGH':>7} {'G_tot':>6}{'G_CRIT':>7}{'G_HIGH':>7} {'OSV':>5}")
for img in DESIGN:
    ts = native(trivy_findings(img)); gs = native(grype_findings(img))
    tc = sum(1 for v in ts.values() if v=='CRITICAL'); th = sum(1 for v in ts.values() if v=='HIGH')
    gc = sum(1 for v in gs.values() if v=='CRITICAL'); gh = sum(1 for v in gs.values() if v=='HIGH')
    print(f"{img:24} {len(ts):6}{tc:7}{th:7} {len(gs):6}{gc:7}{gh:7} {osv_count(img):5}")
