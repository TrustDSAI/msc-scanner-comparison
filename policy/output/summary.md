# Policy comparison matrix

Network probe: OK
Classifiers: rule, agent

## Classifier: rule

| Group | Image | CRIT | app/os/? | P1 | P2 | P3 | P4_strict | P4_relaxed | P5_layer | P7_severity_aware |
|-------|-------|------|----------|---|---|---|---|---|---|---|
| C | alpine:3.19 | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | nginx:1.29.7 | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | node:20 | 33 | 0/33/0 | **B** (33) | pass (0) | **B** (32) | pass (0) | **B** (1) | **B** (1) | **B** (1) |
| C | python:3.12 | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| B | nginx:1.19 | 42 | 0/42/0 | **B** (42) | **B** (40) | **B** (41) | pass (0) | **B** (10) | **B** (10) | **B** (16) |
| B | node:14 | 23 | 1/21/1 | **B** (23) | **B** (18) | **B** (20) | pass (0) | **B** (12) | **B** (12) | **B** (22) |
| B | python:3.8 | 191 | 0/190/1 | **B** (191) | **B** (158) | **B** (187) | pass (0) | **B** (6) | **B** (6) | **B** (11) |
| A | vulnerables/web-dvwa | 328 | 0/328/0 | **B** (328) | **B** (266) | **B** (295) | **B** (15) | **B** (87) | **B** (87) | **B** (133) |
| A | bkimminich/juice-shop | 9 | 9/0/0 | **B** (9) | **B** (7) | **B** (9) | pass (0) | **B** (1) | pass (0) | pass (0) |
| A | policy-gate-val/v01-log4shell:latest | 4 | 4/0/0 | **B** (4) | **B** (4) | pass (0) | pass (0) | pass (0) | pass (0) | **B** (4) |
| A | policy-gate-val/v03-text4shell:latest | 2 | 2/0/0 | **B** (2) | **B** (2) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| A | policy-gate-val/v04-spring4shell:latest | 6 | 6/0/0 | **B** (6) | **B** (6) | pass (0) | pass (0) | pass (0) | pass (0) | **B** (4) |
| A | webgoat/webgoat-8.0 | 107 | 42/65/0 | **B** (107) | **B** (75) | **B** (40) | pass (0) | **B** (11) | **B** (11) | **B** (26) |
| A | citizenstig/nowasp:latest | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| B | golang:1.16-alpine | 9 | 4/5/0 | **B** (9) | **B** (5) | **B** (1) | pass (0) | **B** (1) | **B** (1) | **B** (7) |
| B | ruby:2.5-slim | 30 | 0/27/3 | **B** (30) | **B** (27) | **B** (28) | pass (0) | **B** (12) | **B** (12) | **B** (33) |
| B | eclipse-temurin:8-jre | 1 | 1/0/0 | **B** (1) | **B** (1) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| B | mcr.microsoft.com/dotnet/runtime:3.1 | 5 | 0/5/0 | **B** (5) | **B** (3) | **B** (4) | pass (0) | **B** (3) | **B** (3) | **B** (8) |
| B | php:7.4-apache | 96 | 0/88/8 | **B** (96) | **B** (74) | **B** (82) | **B** (4) | **B** (17) | **B** (17) | **B** (44) |
| B | rust:1.56-slim | 41 | 0/40/1 | **B** (41) | **B** (32) | **B** (33) | pass (0) | **B** (7) | **B** (7) | **B** (28) |
| B | node:12 | 72 | 3/68/1 | **B** (72) | **B** (11) | **B** (29) | pass (0) | **B** (7) | **B** (7) | **B** (7) |
| B | python:2.7 | 184 | 0/180/4 | **B** (184) | **B** (178) | **B** (176) | pass (0) | **B** (85) | **B** (85) | **B** (135) |
| C | golang:1.23-alpine | 8 | 2/4/2 | **B** (8) | **B** (8) | **B** (5) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | ruby:3.3-slim | 7 | 0/5/2 | **B** (7) | **B** (2) | **B** (7) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | eclipse-temurin:21-jre | 1 | 1/0/0 | **B** (1) | **B** (1) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | mcr.microsoft.com/dotnet/runtime:8.0 | 6 | 0/6/0 | **B** (6) | pass (0) | **B** (5) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | php:8.3-apache | 30 | 0/30/0 | **B** (30) | pass (0) | **B** (29) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | rust:1.82-slim | 18 | 0/18/0 | **B** (18) | **B** (9) | **B** (13) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | node:22 | 41 | 0/41/0 | **B** (41) | pass (0) | **B** (39) | pass (0) | **B** (1) | **B** (1) | **B** (1) |
| C | python:3.13-slim | 6 | 0/5/1 | **B** (6) | pass (0) | **B** (5) | pass (0) | pass (0) | pass (0) | pass (0) |

## Classifier: agent

| Group | Image | CRIT | app/os/? | P1 | P2 | P3 | P4_strict | P4_relaxed | P5_layer | P7_severity_aware |
|-------|-------|------|----------|---|---|---|---|---|---|---|
| C | alpine:3.19 | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | nginx:1.29.7 | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | node:20 | 33 | 0/33/0 | **B** (33) | pass (0) | **B** (32) | pass (0) | **B** (1) | **B** (1) | **B** (1) |
| C | python:3.12 | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| B | nginx:1.19 | 42 | 0/42/0 | **B** (42) | **B** (40) | **B** (41) | pass (0) | **B** (10) | **B** (10) | **B** (16) |
| B | node:14 | 23 | 2/21/0 | **B** (23) | **B** (18) | **B** (20) | pass (0) | **B** (12) | **B** (12) | **B** (22) |
| B | python:3.8 | 191 | 0/191/0 | **B** (191) | **B** (158) | **B** (187) | pass (0) | **B** (6) | **B** (6) | **B** (11) |
| A | vulnerables/web-dvwa | 328 | 122/206/0 | **B** (328) | **B** (266) | **B** (295) | **B** (15) | **B** (87) | **B** (62) | **B** (108) |
| A | bkimminich/juice-shop | 9 | 9/0/0 | **B** (9) | **B** (7) | **B** (9) | pass (0) | **B** (1) | pass (0) | pass (0) |
| A | policy-gate-val/v01-log4shell:latest | 4 | 4/0/0 | **B** (4) | **B** (4) | pass (0) | pass (0) | pass (0) | pass (0) | **B** (4) |
| A | policy-gate-val/v03-text4shell:latest | 2 | 2/0/0 | **B** (2) | **B** (2) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| A | policy-gate-val/v04-spring4shell:latest | 6 | 6/0/0 | **B** (6) | **B** (6) | pass (0) | pass (0) | pass (0) | pass (0) | **B** (4) |
| A | webgoat/webgoat-8.0 | 107 | 42/65/0 | **B** (107) | **B** (75) | **B** (40) | pass (0) | **B** (11) | **B** (11) | **B** (26) |
| A | citizenstig/nowasp:latest | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| B | golang:1.16-alpine | 9 | 4/5/0 | **B** (9) | **B** (5) | **B** (1) | pass (0) | **B** (1) | **B** (1) | **B** (7) |
| B | ruby:2.5-slim | 30 | 2/28/0 | **B** (30) | **B** (27) | **B** (28) | pass (0) | **B** (12) | **B** (12) | **B** (33) |
| B | eclipse-temurin:8-jre | 1 | 1/0/0 | **B** (1) | **B** (1) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| B | mcr.microsoft.com/dotnet/runtime:3.1 | 5 | 0/5/0 | **B** (5) | **B** (3) | **B** (4) | pass (0) | **B** (3) | **B** (3) | **B** (8) |
| B | php:7.4-apache | 96 | 4/92/0 | **B** (96) | **B** (74) | **B** (82) | **B** (4) | **B** (17) | **B** (17) | **B** (44) |
| B | rust:1.56-slim | 41 | 0/41/0 | **B** (41) | **B** (32) | **B** (33) | pass (0) | **B** (7) | **B** (7) | **B** (28) |
| B | node:12 | 72 | 4/68/0 | **B** (72) | **B** (11) | **B** (29) | pass (0) | **B** (7) | **B** (7) | **B** (7) |
| B | python:2.7 | 184 | 0/184/0 | **B** (184) | **B** (178) | **B** (176) | pass (0) | **B** (85) | **B** (85) | **B** (135) |
| C | golang:1.23-alpine | 8 | 4/4/0 | **B** (8) | **B** (8) | **B** (5) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | ruby:3.3-slim | 7 | 2/5/0 | **B** (7) | **B** (2) | **B** (7) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | eclipse-temurin:21-jre | 1 | 1/0/0 | **B** (1) | **B** (1) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | mcr.microsoft.com/dotnet/runtime:8.0 | 6 | 0/6/0 | **B** (6) | pass (0) | **B** (5) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | php:8.3-apache | 30 | 0/30/0 | **B** (30) | pass (0) | **B** (29) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | rust:1.82-slim | 18 | 0/18/0 | **B** (18) | **B** (9) | **B** (13) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | node:22 | 41 | 0/41/0 | **B** (41) | pass (0) | **B** (39) | pass (0) | **B** (1) | **B** (1) | **B** (1) |
| C | python:3.13-slim | 6 | 0/6/0 | **B** (6) | pass (0) | **B** (5) | pass (0) | pass (0) | pass (0) | pass (0) |

## Suppression workflow demo (tri-state gate)

`policy/exceptions/example-vm2.yaml` suppresses CVE-2023-32314 on bkimminich/juice-shop only; all other images are unaffected.

| Image | Classifier | Run | Block | Deny (block+review) | Suppressed |
|-------|------------|-----|-------|----------------------|------------|
| alpine:3.19 | rule | p_gate | pass | 0 | 0 |
| alpine:3.19 | rule | p_gate_with_exceptions | pass | 0 | 0 |
| alpine:3.19 | agent | p_gate | pass | 0 | 0 |
| alpine:3.19 | agent | p_gate_with_exceptions | pass | 0 | 0 |
| nginx:1.29.7 | rule | p_gate | pass | 0 | 0 |
| nginx:1.29.7 | rule | p_gate_with_exceptions | pass | 0 | 0 |
| nginx:1.29.7 | agent | p_gate | pass | 0 | 0 |
| nginx:1.29.7 | agent | p_gate_with_exceptions | pass | 0 | 0 |
| node:20 | rule | p_gate | pass | 44 | 0 |
| node:20 | rule | p_gate_with_exceptions | pass | 44 | 0 |
| node:20 | agent | p_gate | pass | 44 | 0 |
| node:20 | agent | p_gate_with_exceptions | pass | 44 | 0 |
| python:3.12 | rule | p_gate | pass | 78 | 0 |
| python:3.12 | rule | p_gate_with_exceptions | pass | 78 | 0 |
| python:3.12 | agent | p_gate | pass | 78 | 0 |
| python:3.12 | agent | p_gate_with_exceptions | pass | 78 | 0 |
| nginx:1.19 | rule | p_gate | **BLOCK** | 162 | 0 |
| nginx:1.19 | rule | p_gate_with_exceptions | **BLOCK** | 162 | 0 |
| nginx:1.19 | agent | p_gate | **BLOCK** | 162 | 0 |
| nginx:1.19 | agent | p_gate_with_exceptions | **BLOCK** | 162 | 0 |
| node:14 | rule | p_gate | **BLOCK** | 313 | 0 |
| node:14 | rule | p_gate_with_exceptions | **BLOCK** | 313 | 0 |
| node:14 | agent | p_gate | **BLOCK** | 312 | 0 |
| node:14 | agent | p_gate_with_exceptions | **BLOCK** | 312 | 0 |
| python:3.8 | rule | p_gate | pass | 668 | 0 |
| python:3.8 | rule | p_gate_with_exceptions | pass | 668 | 0 |
| python:3.8 | agent | p_gate | pass | 667 | 0 |
| python:3.8 | agent | p_gate_with_exceptions | pass | 667 | 0 |
| vulnerables/web-dvwa | rule | p_gate | **BLOCK** | 773 | 0 |
| vulnerables/web-dvwa | rule | p_gate_with_exceptions | **BLOCK** | 773 | 0 |
| vulnerables/web-dvwa | agent | p_gate | **BLOCK** | 773 | 0 |
| vulnerables/web-dvwa | agent | p_gate_with_exceptions | **BLOCK** | 773 | 0 |
| bkimminich/juice-shop | rule | p_gate | pass | 41 | 0 |
| bkimminich/juice-shop | rule | p_gate_with_exceptions | pass | 40 | 1 |
| bkimminich/juice-shop | agent | p_gate | pass | 41 | 0 |
| bkimminich/juice-shop | agent | p_gate_with_exceptions | pass | 40 | 1 |
| policy-gate-val/v01-log4shell:latest | rule | p_gate | **BLOCK** | 4 | 0 |
| policy-gate-val/v01-log4shell:latest | rule | p_gate_with_exceptions | **BLOCK** | 4 | 0 |
| policy-gate-val/v01-log4shell:latest | agent | p_gate | **BLOCK** | 4 | 0 |
| policy-gate-val/v01-log4shell:latest | agent | p_gate_with_exceptions | **BLOCK** | 4 | 0 |
| policy-gate-val/v03-text4shell:latest | rule | p_gate | pass | 2 | 0 |
| policy-gate-val/v03-text4shell:latest | rule | p_gate_with_exceptions | pass | 2 | 0 |
| policy-gate-val/v03-text4shell:latest | agent | p_gate | pass | 2 | 0 |
| policy-gate-val/v03-text4shell:latest | agent | p_gate_with_exceptions | pass | 2 | 0 |
| policy-gate-val/v04-spring4shell:latest | rule | p_gate | **BLOCK** | 4 | 0 |
| policy-gate-val/v04-spring4shell:latest | rule | p_gate_with_exceptions | **BLOCK** | 4 | 0 |
| policy-gate-val/v04-spring4shell:latest | agent | p_gate | **BLOCK** | 4 | 0 |
| policy-gate-val/v04-spring4shell:latest | agent | p_gate_with_exceptions | **BLOCK** | 4 | 0 |
| webgoat/webgoat-8.0 | rule | p_gate | **BLOCK** | 160 | 0 |
| webgoat/webgoat-8.0 | rule | p_gate_with_exceptions | **BLOCK** | 160 | 0 |
| webgoat/webgoat-8.0 | agent | p_gate | **BLOCK** | 160 | 0 |
| webgoat/webgoat-8.0 | agent | p_gate_with_exceptions | **BLOCK** | 160 | 0 |
| citizenstig/nowasp:latest | rule | p_gate | pass | 6 | 0 |
| citizenstig/nowasp:latest | rule | p_gate_with_exceptions | pass | 6 | 0 |
| citizenstig/nowasp:latest | agent | p_gate | pass | 6 | 0 |
| citizenstig/nowasp:latest | agent | p_gate_with_exceptions | pass | 6 | 0 |
| golang:1.16-alpine | rule | p_gate | pass | 19 | 0 |
| golang:1.16-alpine | rule | p_gate_with_exceptions | pass | 19 | 0 |
| golang:1.16-alpine | agent | p_gate | pass | 19 | 0 |
| golang:1.16-alpine | agent | p_gate_with_exceptions | pass | 19 | 0 |
| ruby:2.5-slim | rule | p_gate | **BLOCK** | 119 | 0 |
| ruby:2.5-slim | rule | p_gate_with_exceptions | **BLOCK** | 119 | 0 |
| ruby:2.5-slim | agent | p_gate | **BLOCK** | 119 | 0 |
| ruby:2.5-slim | agent | p_gate_with_exceptions | **BLOCK** | 119 | 0 |
| eclipse-temurin:8-jre | rule | p_gate | pass | 1 | 0 |
| eclipse-temurin:8-jre | rule | p_gate_with_exceptions | pass | 1 | 0 |
| eclipse-temurin:8-jre | agent | p_gate | pass | 1 | 0 |
| eclipse-temurin:8-jre | agent | p_gate_with_exceptions | pass | 1 | 0 |
| mcr.microsoft.com/dotnet/runtime:3.1 | rule | p_gate | pass | 42 | 0 |
| mcr.microsoft.com/dotnet/runtime:3.1 | rule | p_gate_with_exceptions | pass | 42 | 0 |
| mcr.microsoft.com/dotnet/runtime:3.1 | agent | p_gate | pass | 42 | 0 |
| mcr.microsoft.com/dotnet/runtime:3.1 | agent | p_gate_with_exceptions | pass | 42 | 0 |
| php:7.4-apache | rule | p_gate | **BLOCK** | 372 | 0 |
| php:7.4-apache | rule | p_gate_with_exceptions | **BLOCK** | 372 | 0 |
| php:7.4-apache | agent | p_gate | **BLOCK** | 368 | 0 |
| php:7.4-apache | agent | p_gate_with_exceptions | **BLOCK** | 368 | 0 |
| rust:1.56-slim | rule | p_gate | pass | 180 | 0 |
| rust:1.56-slim | rule | p_gate_with_exceptions | pass | 180 | 0 |
| rust:1.56-slim | agent | p_gate | pass | 180 | 0 |
| rust:1.56-slim | agent | p_gate_with_exceptions | pass | 180 | 0 |
| node:12 | rule | p_gate | **BLOCK** | 117 | 0 |
| node:12 | rule | p_gate_with_exceptions | **BLOCK** | 117 | 0 |
| node:12 | agent | p_gate | **BLOCK** | 116 | 0 |
| node:12 | agent | p_gate_with_exceptions | **BLOCK** | 116 | 0 |
| python:2.7 | rule | p_gate | **BLOCK** | 1303 | 0 |
| python:2.7 | rule | p_gate_with_exceptions | **BLOCK** | 1303 | 0 |
| python:2.7 | agent | p_gate | **BLOCK** | 1302 | 0 |
| python:2.7 | agent | p_gate_with_exceptions | **BLOCK** | 1302 | 0 |
| golang:1.23-alpine | rule | p_gate | pass | 63 | 0 |
| golang:1.23-alpine | rule | p_gate_with_exceptions | pass | 63 | 0 |
| golang:1.23-alpine | agent | p_gate | pass | 61 | 0 |
| golang:1.23-alpine | agent | p_gate_with_exceptions | pass | 61 | 0 |
| ruby:3.3-slim | rule | p_gate | pass | 10 | 0 |
| ruby:3.3-slim | rule | p_gate_with_exceptions | pass | 10 | 0 |
| ruby:3.3-slim | agent | p_gate | pass | 10 | 0 |
| ruby:3.3-slim | agent | p_gate_with_exceptions | pass | 10 | 0 |
| eclipse-temurin:21-jre | rule | p_gate | pass | 1 | 0 |
| eclipse-temurin:21-jre | rule | p_gate_with_exceptions | pass | 1 | 0 |
| eclipse-temurin:21-jre | agent | p_gate | pass | 1 | 0 |
| eclipse-temurin:21-jre | agent | p_gate_with_exceptions | pass | 1 | 0 |
| mcr.microsoft.com/dotnet/runtime:8.0 | rule | p_gate | pass | 6 | 0 |
| mcr.microsoft.com/dotnet/runtime:8.0 | rule | p_gate_with_exceptions | pass | 6 | 0 |
| mcr.microsoft.com/dotnet/runtime:8.0 | agent | p_gate | pass | 6 | 0 |
| mcr.microsoft.com/dotnet/runtime:8.0 | agent | p_gate_with_exceptions | pass | 6 | 0 |
| php:8.3-apache | rule | p_gate | pass | 29 | 0 |
| php:8.3-apache | rule | p_gate_with_exceptions | pass | 29 | 0 |
| php:8.3-apache | agent | p_gate | pass | 29 | 0 |
| php:8.3-apache | agent | p_gate_with_exceptions | pass | 29 | 0 |
| rust:1.82-slim | rule | p_gate | pass | 92 | 0 |
| rust:1.82-slim | rule | p_gate_with_exceptions | pass | 92 | 0 |
| rust:1.82-slim | agent | p_gate | pass | 92 | 0 |
| rust:1.82-slim | agent | p_gate_with_exceptions | pass | 92 | 0 |
| node:22 | rule | p_gate | pass | 41 | 0 |
| node:22 | rule | p_gate_with_exceptions | pass | 41 | 0 |
| node:22 | agent | p_gate | pass | 41 | 0 |
| node:22 | agent | p_gate_with_exceptions | pass | 41 | 0 |
| python:3.13-slim | rule | p_gate | pass | 6 | 0 |
| python:3.13-slim | rule | p_gate_with_exceptions | pass | 6 | 0 |
| python:3.13-slim | agent | p_gate | pass | 5 | 0 |
| python:3.13-slim | agent | p_gate_with_exceptions | pass | 5 | 0 |

## Classifier comparison (CRITICAL findings only)

| Image | Agent | rule app/os/? | agent app/os/? |
|-------|-------|---------------|----------------|
| alpine:3.19 | agent | 0/0/0 | 0/0/0 |
| nginx:1.29.7 | agent | 0/0/0 | 0/0/0 |
| node:20 | agent | 0/33/0 | 0/33/0 |
| python:3.12 | agent | 0/0/0 | 0/0/0 |
| nginx:1.19 | agent | 0/42/0 | 0/42/0 |
| node:14 | agent | 1/21/1 | 2/21/0 |
| python:3.8 | agent | 0/190/1 | 0/191/0 |
| vulnerables/web-dvwa | agent | 0/328/0 | 122/206/0 |
| bkimminich/juice-shop | agent | 9/0/0 | 9/0/0 |
| policy-gate-val/v01-log4shell:latest | agent | 4/0/0 | 4/0/0 |
| policy-gate-val/v03-text4shell:latest | agent | 2/0/0 | 2/0/0 |
| policy-gate-val/v04-spring4shell:latest | agent | 6/0/0 | 6/0/0 |
| webgoat/webgoat-8.0 | agent | 42/65/0 | 42/65/0 |
| citizenstig/nowasp:latest | agent | 0/0/0 | 0/0/0 |
| golang:1.16-alpine | agent | 4/5/0 | 4/5/0 |
| ruby:2.5-slim | agent | 0/27/3 | 2/28/0 |
| eclipse-temurin:8-jre | agent | 1/0/0 | 1/0/0 |
| mcr.microsoft.com/dotnet/runtime:3.1 | agent | 0/5/0 | 0/5/0 |
| php:7.4-apache | agent | 0/88/8 | 4/92/0 |
| rust:1.56-slim | agent | 0/40/1 | 0/41/0 |
| node:12 | agent | 3/68/1 | 4/68/0 |
| python:2.7 | agent | 0/180/4 | 0/184/0 |
| golang:1.23-alpine | agent | 2/4/2 | 4/4/0 |
| ruby:3.3-slim | agent | 0/5/2 | 2/5/0 |
| eclipse-temurin:21-jre | agent | 1/0/0 | 1/0/0 |
| mcr.microsoft.com/dotnet/runtime:8.0 | agent | 0/6/0 | 0/6/0 |
| php:8.3-apache | agent | 0/30/0 | 0/30/0 |
| rust:1.82-slim | agent | 0/18/0 | 0/18/0 |
| node:22 | agent | 0/41/0 | 0/41/0 |
| python:3.13-slim | agent | 0/5/1 | 0/6/0 |
