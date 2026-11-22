# Network scan report: nmap-edge.xml

- Scan date: 2026-11-22 07:21 UTC
- Command: `/usr/bin/nmap -sT -Pn -p- --open -T4 -oX /reports/nmap-edge.xml 172.28.10.10`
- Hosts up: **1**, open ports: **2**
- Risks: **0 critical**, 0 high, 0 medium, 1 low

## Risks

| Severity | Host | Port | Finding | Why it matters | Fix |
|---|---|---|---|---|---|
| low | 172.28.10.10 (ism-caddy-1.ism_edge) | 80/tcp | Plain HTTP service | Traffic and logins on this port are not encrypted. | Redirect to HTTPS (see web-sec-check). |

## Hosts

### 172.28.10.10 (ism-caddy-1.ism_edge)

| Port | Service | Version |
|---|---|---|
| 80/tcp | http |  |
| 443/tcp | https |  |
