import sys,csv,os; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
MAP={'alpine_3.19':'alpine:3.19','nginx_1.29.7':'nginx:1.29.7','node_20':'node:20','python_3.12':'python:3.12',
'nginx_1.19':'nginx:1.19','node_14':'node:14','python_3.8':'python:3.8','vulnerables_web-dvwa':'vulnerables/web-dvwa',
'bkimminich_juice-shop':'bkimminich/juice-shop','v01_log4shell':'policy-gate-val/v01-log4shell:latest',
'v03_text4shell':'policy-gate-val/v03-text4shell:latest','v04_spring4shell':'policy-gate-val/v04-spring4shell:latest',
'webgoat_webgoat':'webgoat/webgoat-8.0','citizenstig_nowasp':'citizenstig/nowasp:latest','golang_1.16-alpine':'golang:1.16-alpine',
'ruby_2.5-slim':'ruby:2.5-slim','eclipse-temurin_8-jre':'eclipse-temurin:8-jre','dotnet_runtime_3.1':'mcr.microsoft.com/dotnet/runtime:3.1',
'php_7.4-apache':'php:7.4-apache','rust_1.56-slim':'rust:1.56-slim','node_12':'node:12','python_2.7':'python:2.7',
'golang_1.23-alpine':'golang:1.23-alpine','ruby_3.3-slim':'ruby:3.3-slim','eclipse-temurin_21-jre':'eclipse-temurin:21-jre',
'dotnet_runtime_8.0':'mcr.microsoft.com/dotnet/runtime:8.0','php_8.3-apache':'php:8.3-apache','rust_1.82-slim':'rust:1.82-slim',
'node_22':'node:22','python_3.13-slim':'python:3.13-slim'}
p=os.path.expanduser('~/msc-scanner-comparison/policy/output/verdict_matrix.csv')
r=list(csv.DictReader(open(p)))
idx={(x['image'],x['classifier'],x['policy']):x for x in r}
trivy_b=set(); grype_b=set(); fixable_b=set(); p1_b=set(); gate_b=set()
merged_crit_total=0
for safe in images():
    disp=MAP[safe]
    tf=trivy_findings(safe); gf=grype_findings(safe)
    ts=native(tf); gs=native(gf)
    tc=sum(1 for v in ts.values() if v=='CRITICAL'); gc=sum(1 for v in gs.values() if v=='CRITICAL')
    if tc>0: trivy_b.add(disp)
    if gc>0: grype_b.add(disp)
    fixT=any(f['fixed'] for f in tf if f['sev']=='CRITICAL')
    fixG=any(f['fixed'] for f in gf if f['sev']=='CRITICAL')
    if fixT or fixG: fixable_b.add(disp)
    if idx[(disp,'rule','P1')]['block']=='True': p1_b.add(disp)
    merged_crit_total+=int(idx[(disp,'rule','P1')]['critical_total'])
    if idx[(disp,'rule','p_gate')]['block']=='True': gate_b.add(disp)
print("grype --fail-on critical (native) blocks:",len(grype_b))
print("P1 merged any-CRITICAL blocks:",len(p1_b))
print("trivy --severity CRITICAL blocks:",len(trivy_b))
print("Fixable CRITICAL either tool blocks:",len(fixable_b))
print("p_gate blocks:",len(gate_b))
print()
print("P1 set == Grype set ?", p1_b==grype_b)
print("  P1 - Grype:",sorted(p1_b-grype_b))
print("  Grype - P1:",sorted(grype_b-p1_b))
print("Grype - Trivy (grype blocks, trivy doesn't):",sorted(grype_b-trivy_b))
print("Trivy - Grype:",sorted(trivy_b-grype_b))
print()
print("total merged CRITICAL findings across 30 images:",merged_crit_total)
tnat=sum(sum(1 for v in native(trivy_findings(s)).values() if v=='CRITICAL') for s in images())
gnat=sum(sum(1 for v in native(grype_findings(s)).values() if v=='CRITICAL') for s in images())
print("total native CRITICAL: trivy",tnat,"grype",gnat)
