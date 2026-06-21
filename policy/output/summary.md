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
| B | nginx:1.19 | 42 | 0/42/0 | **B** (42) | **B** (40) | **B** (41) | pass (0) | **B** (5) | **B** (5) | **B** (11) |
| B | node:14 | 23 | 1/21/1 | **B** (23) | **B** (18) | **B** (20) | pass (0) | **B** (1) | **B** (1) | **B** (11) |
| B | python:3.8 | 191 | 0/190/1 | **B** (191) | **B** (158) | **B** (187) | pass (0) | **B** (6) | **B** (6) | **B** (11) |
| A | vulnerables/web-dvwa | 328 | 0/328/0 | **B** (328) | **B** (266) | **B** (295) | **B** (4) | **B** (30) | **B** (30) | **B** (76) |
| A | bkimminich/juice-shop | 9 | 9/0/0 | **B** (9) | **B** (7) | **B** (9) | pass (0) | pass (0) | pass (0) | pass (0) |

## Classifier: agent

| Group | Image | CRIT | app/os/? | P1 | P2 | P3 | P4_strict | P4_relaxed | P5_layer | P7_severity_aware |
|-------|-------|------|----------|---|---|---|---|---|---|---|
| C | alpine:3.19 | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | nginx:1.29.7 | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| C | node:20 | 33 | 0/33/0 | **B** (33) | pass (0) | **B** (32) | pass (0) | **B** (1) | **B** (1) | **B** (1) |
| C | python:3.12 | 0 | 0/0/0 | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) | pass (0) |
| B | nginx:1.19 | 42 | 0/42/0 | **B** (42) | **B** (40) | **B** (41) | pass (0) | **B** (5) | **B** (5) | **B** (11) |
| B | node:14 | 23 | 2/21/0 | **B** (23) | **B** (18) | **B** (20) | pass (0) | **B** (1) | **B** (1) | **B** (11) |
| B | python:3.8 | 191 | 0/191/0 | **B** (191) | **B** (158) | **B** (187) | pass (0) | **B** (6) | **B** (6) | **B** (11) |
| A | vulnerables/web-dvwa | 328 | 122/206/0 | **B** (328) | **B** (266) | **B** (295) | **B** (4) | **B** (30) | **B** (22) | **B** (68) |
| A | bkimminich/juice-shop | 9 | 9/0/0 | **B** (9) | **B** (7) | **B** (9) | pass (0) | pass (0) | pass (0) | pass (0) |

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
| node:20 | rule | p_gate | pass | 13 | 0 |
| node:20 | rule | p_gate_with_exceptions | pass | 13 | 0 |
| node:20 | agent | p_gate | pass | 13 | 0 |
| node:20 | agent | p_gate_with_exceptions | pass | 13 | 0 |
| python:3.12 | rule | p_gate | pass | 78 | 0 |
| python:3.12 | rule | p_gate_with_exceptions | pass | 78 | 0 |
| python:3.12 | agent | p_gate | pass | 78 | 0 |
| python:3.12 | agent | p_gate_with_exceptions | pass | 78 | 0 |
| nginx:1.19 | rule | p_gate | **BLOCK** | 138 | 0 |
| nginx:1.19 | rule | p_gate_with_exceptions | **BLOCK** | 138 | 0 |
| nginx:1.19 | agent | p_gate | **BLOCK** | 138 | 0 |
| nginx:1.19 | agent | p_gate_with_exceptions | **BLOCK** | 138 | 0 |
| node:14 | rule | p_gate | pass | 307 | 0 |
| node:14 | rule | p_gate_with_exceptions | pass | 307 | 0 |
| node:14 | agent | p_gate | pass | 306 | 0 |
| node:14 | agent | p_gate_with_exceptions | pass | 306 | 0 |
| python:3.8 | rule | p_gate | pass | 490 | 0 |
| python:3.8 | rule | p_gate_with_exceptions | pass | 490 | 0 |
| python:3.8 | agent | p_gate | pass | 489 | 0 |
| python:3.8 | agent | p_gate_with_exceptions | pass | 489 | 0 |
| vulnerables/web-dvwa | rule | p_gate | **BLOCK** | 707 | 0 |
| vulnerables/web-dvwa | rule | p_gate_with_exceptions | **BLOCK** | 707 | 0 |
| vulnerables/web-dvwa | agent | p_gate | **BLOCK** | 625 | 0 |
| vulnerables/web-dvwa | agent | p_gate_with_exceptions | **BLOCK** | 625 | 0 |
| bkimminich/juice-shop | rule | p_gate | pass | 35 | 0 |
| bkimminich/juice-shop | rule | p_gate_with_exceptions | pass | 34 | 1 |
| bkimminich/juice-shop | agent | p_gate | pass | 35 | 0 |
| bkimminich/juice-shop | agent | p_gate_with_exceptions | pass | 34 | 1 |

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
