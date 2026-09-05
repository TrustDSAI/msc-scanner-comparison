"""Independent re-implementation of the dissertation's native-count metrics.
Written from Section 4.1.5 prose only; does not import the repo's analysis code."""
import json, os, glob, re
from collections import defaultdict

RAW = os.path.expanduser('~/msc-scanner-comparison/data/raw')

def stem(path):
    b = os.path.basename(path)
    return re.sub(r'_(trivy|grype|osv)\.json$', '', b)

def images():
    return sorted(stem(p) for p in glob.glob(f'{RAW}/trivy/*_trivy.json'))

def trivy_findings(img, root=RAW):
    """yield dicts: id, pkg, sev, fixed(bool), cwes"""
    d = json.load(open(f'{root}/trivy/{img}_trivy.json'))
    out = []
    for r in d.get('Results') or []:
        for v in r.get('Vulnerabilities') or []:
            out.append(dict(id=v['VulnerabilityID'], pkg=v.get('PkgName'),
                            sev=(v.get('Severity') or 'UNKNOWN').upper(),
                            fixed=bool(v.get('FixedVersion')),
                            cwes=v.get('CweIDs') or []))
    return out

def grype_canon(m):
    """canonical id per Section 4.1.5: own CVE, else first CVE alias, else raw id"""
    vid = m['vulnerability']['id']
    if vid.startswith('CVE-'):
        return vid
    for rel in m.get('relatedVulnerabilities') or []:
        if rel.get('id', '').startswith('CVE-'):
            return rel['id']
    return vid

def grype_findings(img, root=RAW):
    d = json.load(open(f'{root}/grype/{img}_grype.json'))
    out = []
    for m in d['matches']:
        v = m['vulnerability']
        fix = v.get('fix') or {}
        cwes = []
        for rel in [v] + (m.get('relatedVulnerabilities') or []):
            for c in (rel.get('cvss') or []):
                pass
        out.append(dict(raw=v['id'], id=grype_canon(m), pkg=m['artifact']['name'],
                        sev=(v.get('severity') or 'Unknown').upper(),
                        fixed=fix.get('state') == 'fixed',
                        ns=v.get('namespace'),
                        related=[r['id'] for r in (m.get('relatedVulnerabilities') or [])]))
    return out

def osv_count(img, root=RAW):
    p = f'{root}/osv/{img}_osv.json'
    if not os.path.exists(p): return None
    d = json.load(open(p))
    ids = set()
    for r in d.get('results') or []:
        for pk in r.get('packages') or []:
            for v in pk.get('vulnerabilities') or []:
                ids.add(v['id'])
    return len(ids)

def native(fs):
    """unique-CVE-per-image counts; severity = worst rating seen for that CVE"""
    ORDER = ['UNKNOWN','NEGLIGIBLE','LOW','MEDIUM','HIGH','CRITICAL']
    sev = {}
    for f in fs:
        cur = sev.get(f['id'])
        s = f['sev']
        if s not in ORDER: s = 'UNKNOWN'
        if cur is None or ORDER.index(s) > ORDER.index(cur):
            sev[f['id']] = s
    return sev
