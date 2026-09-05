import sys,os,statistics,json; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
import lib
from scipy.stats import mannwhitneyu
R=os.path.expanduser('~/msc-scanner-comparison/data/raw_rescan_2026-07-29')
print("rescan files:",sorted(os.listdir(R+'/trivy')))
import stats as S
rows=[(s,)+S.measure(s,R) for s in sorted(f.replace('_trivy.json','') for f in os.listdir(R+'/trivy'))]
o=[r[1] for r in rows if r[2]=='os']; m=[r[1] for r in rows if r[2]=='mixed']
u,p=mannwhitneyu(o,m,alternative='greater')
print(f"\nRE-SCAN 2026-07-29: n_os={len(o)} n_mixed={len(m)} mean_os={statistics.mean(o):.4f} mean_mixed={statistics.mean(m):.4f}")
print(f"   U={u} one-tailed p={p:.4f}")
for r in rows: print(f"   {r[0]:24} J={r[1]:.3f} {r[2]}")
