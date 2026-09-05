import sys,json,re,os; sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from lib import *
# PDF Appendix A digests
pdf="""web-dvwa dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7
juice-shop 5539448a1d3fa88d932d3f80a8d3f69a16cde6253c1d4256b28a38ef910e4114
nginx:1.19 df13abe416e37eb3db4722840dd479b00ba193ac6606e7902331dcea50f4f1f2
node:14 a158d3b9b4e3fa813fa6c8c590b8f0a860e015ad4e59bbce5744d2f6fd8461aa
python:3.8 d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c
alpine:3.19 6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1
nginx:1.29.7 7150b3a39203cb5bee612ff4a9d18774f8c7caf6399d6e8985e97e28eb751c18
node:20 a4545fc6f4f1483384ad5f4c71d34d71781c3779da407173ec6058079a718520
python:3.12 c4c9e439bf98d5c20453156194f937aefb4a633555d93a1960d612052c4b3436
v01-log4shell 58afc37413131e10e0f39852fac9eb60f9c63b33beea3cc5cf73efef582d644b
v03-text4shell f3a79fec7904833a726d23bca33b6015ca9ad6c557f9c257bfd8794646726664
v04-spring4shell 29a05320ccf6a553cc2741f328d16a24a2b00738a927b52fb81b2d24f22b2004
webgoat-8.0 e24bcaf41034c28b6a08aba94507a169ae23f2b87899e225a3d18fe8c36d26f5
nowasp 8bf6f283163bbc269ccfff513e4a06776325cb4957f683df9edd4ab98c6966de
golang:1.16-alpine 5616dca835fa90ef13a843824ba58394dad356b7d56198fb7c93cbe76d7d67fe
ruby:2.5-slim adcd8b511b04fd56863443c14c66587b192efe42cf080ef97cea89471b20e9c0
temurin:8-jre 2cf594af1a5f5ffa643554e151f0474ef7c5d083b558bed504392deddc967358
dotnet/runtime:3.1 96d655c489cdf341f7679510efe51a5ba4e174d74aaaf613f7578f2e25c3717d
php:7.4-apache c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d
rust:1.56-slim cc2b5c03d4acf19be7fa8155cae8abbc8c3aa893a5d177ceb4921a3cbbb190da
node:12 01627afeb110b3054ba4a1405541ca095c8bfca1cb6f2be9479c767a2711879e
python:2.7 cfa62318c459b1fde9e0841c619906d15ada5910d625176e24bf692cf8a2601d
golang:1.23-alpine 383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f
ruby:3.3-slim 5340ab7cd6317c45a0a7e2818857b930ff61ee92ffd661dec72738e42dd2cddf
temurin:21-jre 8ec353b20d3aab0758572236b81b967c7077c40c4d0819ce97f9a1329d684603
dotnet/runtime:8.0 d73109ac31761185b1b97af576c78182af9189495c35fa451ed82994c9af23bf
php:8.3-apache 954d6198d9877b396382aa8a93d8be4832ab4908a7dc64f58dcc4be2833b8e29
rust:1.82-slim 1111c28d995d06a7863ba6cea3b3dcb87bebe65af8ec5517caaf2c8c26f38010
node:22 e0d149b4727ac0c20d9774e801e423d7a946a0bffced886f42cfe9cd3c67820a
python:3.13-slim c33f0bc4364a6881bed1ec0cc2665e6c53c87a43e774aaeab88e6f17af105e4f"""
SAFE={'web-dvwa':'vulnerables_web-dvwa','juice-shop':'bkimminich_juice-shop','nginx:1.19':'nginx_1.19',
'node:14':'node_14','python:3.8':'python_3.8','alpine:3.19':'alpine_3.19','nginx:1.29.7':'nginx_1.29.7',
'node:20':'node_20','python:3.12':'python_3.12','v01-log4shell':'v01_log4shell','v03-text4shell':'v03_text4shell',
'v04-spring4shell':'v04_spring4shell','webgoat-8.0':'webgoat_webgoat','nowasp':'citizenstig_nowasp',
'golang:1.16-alpine':'golang_1.16-alpine','ruby:2.5-slim':'ruby_2.5-slim','temurin:8-jre':'eclipse-temurin_8-jre',
'dotnet/runtime:3.1':'dotnet_runtime_3.1','php:7.4-apache':'php_7.4-apache','rust:1.56-slim':'rust_1.56-slim',
'node:12':'node_12','python:2.7':'python_2.7','golang:1.23-alpine':'golang_1.23-alpine','ruby:3.3-slim':'ruby_3.3-slim',
'temurin:21-jre':'eclipse-temurin_21-jre','dotnet/runtime:8.0':'dotnet_runtime_8.0','php:8.3-apache':'php_8.3-apache',
'rust:1.82-slim':'rust_1.82-slim','node:22':'node_22','python:3.13-slim':'python_3.13-slim'}
# digests.log
log={}
for ln in open(os.path.expanduser('~/msc-scanner-comparison/logs/digests.log')):
    p=ln.split()
    if len(p)>=4:
        safe=p[1]; dg=p[3].split('sha256:')[-1]
        log[safe]=dg
log['nginx_1.29.7']=log.pop('nginx_latest',log.get('nginx_1.29.7'))
ok=bad=miss=0
for ln in pdf.strip().split('\n'):
    name,dg=ln.rsplit(' ',1)
    safe=SAFE[name]
    # scanner-recorded digest
    tj=json.load(open(f'{RAW}/trivy/{safe}_trivy.json'))
    rd=(tj['Metadata'].get('RepoDigests') or [])
    scanned = rd[0].split('sha256:')[-1] if rd else (tj.get('ArtifactID','').split('sha256:')[-1])
    l=log.get(safe)
    st_log = 'OK' if l==dg else f'LOGMISMATCH({l})'
    st_scan = 'OK' if scanned==dg else f'SCANMISMATCH({scanned[:16]}..)'
    if st_log=='OK' and st_scan=='OK': ok+=1
    else: bad+=1; print(f"  {name:22} log={st_log} scan={st_scan}")
print(f"digest check: {ok} exact match (Appendix A == digests.log == scanned RepoDigest/ArtifactID), {bad} mismatch")
