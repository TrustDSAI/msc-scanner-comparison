import sys,json,collections; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
g=json.load(open(f'{RAW}/grype/bkimminich_juice-shop_grype.json'))
gh=[m for m in g['matches'] if 'github' in (m['vulnerability'].get('namespace') or '')]
withalias=[m for m in gh if any(r['id'].startswith('CVE-') for r in (m.get('relatedVulnerabilities') or []))]
noalias=[m for m in gh if m not in withalias]
canon=set(grype_canon(m) for m in withalias)
T=set(f['id'] for f in trivy_findings('bkimminich_juice-shop'))
print("total grype matches",len(g['matches']))
print("GHSA-namespace matches",len(gh))
print("  with a CVE alias",len(withalias),"  without",len(noalias))
print("  unique canonical CVEs from those",len(canon))
print("  of which Trivy also reports",len(canon&T),"; missing",sorted(canon-T))
print("  no-alias raw ids:",[m['vulnerability']['id'] for m in noalias])
print("\n--- node:14 binutils family")
gf=grype_findings('node_14'); tf=trivy_findings('node_14')
T=set(f['id'] for f in tf); G=set(f['id'] for f in gf)
tp={f['pkg'] for f in tf}
for p in ['binutils','libbinutils','binutils-common','binutils-x86-64-linux-gnu']:
    ids={f['id'] for f in gf if f['pkg']==p}
    print(f"  {p:28} grype CVEs={len(ids):4} shared_with_trivy={len(ids&T):4} in_trivy_pkglist={p in tp}")
print("\n--- runtime binary findings (nvd:cpe namespace)")
for img in ['node_14','python_3.12']:
    gf=grype_findings(img)
    n=[f for f in gf if f['ns']=='nvd:cpe']
    print(f"  {img:12} nvd:cpe matches={len(n)} unique CVEs={len({f['id'] for f in n})} pkgs={ {f['pkg'] for f in n} }")
