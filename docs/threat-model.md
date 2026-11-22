# Threat model (STRIDE)

Scope: the single-host stack in this repository as it would run on a VPS:
Caddy (public), crm-demo API, PostgreSQL, monitoring and logging plane,
backup job. Out of scope: the application's own business logic (covered by
crm-demo's tests and pentest report), the cloud provider, the admin laptop.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Customer and order data in PostgreSQL | personal data (names, phones), business records |
| Credentials: DB password, JWT secret, Grafana admin, restic password, lab CA key | each one unlocks a layer |
| Backups | the only way back after ransomware or operator error |
| Logs and metrics | evidence for incident response; must not be tampered with or lost |
| Host and Docker daemon | root on the host = everything above |

## Trust boundaries

1. Internet -> Caddy (80/443) — the only public boundary.
2. Caddy -> application network.
3. Application -> database network.
4. Monitoring network (internal, no Internet).
5. Docker API, reachable only through the read-only socket proxy.
6. Admin -> host via SSH from the VPN subnet only.

## Threats and controls

| STRIDE | Threat | Control | Verified by |
|--------|--------|---------|-------------|
| **S**poofing | Client fakes its IP via `X-Forwarded-For` to dodge rate limits or poison the audit log | Caddy overwrites XFF with the TCP peer address; app trusts only the right-most entry | `BRUTE-THROTTLE`, `DET-BRUTE` (alert shows the real IP while the scanner sent fake ones) |
| Spoofing | Password brute force against the CRM | App lockout + per-IP rate limit; Loki alert `CRMLoginBruteForce` (T1110) | `BRUTE-THROTTLE`, `DET-BRUTE`, `NOTIFY` |
| Spoofing | Brute force against SSH | SSH only from VPN subnet; nftables dynamic blocklist | `firewall-test.txt` |
| **T**ampering | MITM / downgrade on the wire | TLS 1.2/1.3 only, HSTS 1 year, HTTP -> HTTPS 308 | `TLS-*`, `HTTP-REDIRECT`, `HDR-SECURITY`, black-box probes |
| Tampering | Attacker deletes backups after compromising the host | Encrypted restic repo; production: off-host, append-only credentials (ADR 0005) | design only in the lab |
| **R**epudiation | No trace of who did what | Caddy JSON access logs + app audit log, shipped off the container to Loki, 30-day retention | `LOKI` |
| **I**nformation disclosure | Internal services (DB, Prometheus, Loki) reachable from outside | Internal networks, single published service, DOCKER-USER rules | `PORTS`, `NMAP`, `NET-*` |
| Information disclosure | Version banners, API schema | `-Server`, `/docs` and `/openapi.json` blocked at the proxy | `HDR-BANNER`, `PATH-*` |
| Information disclosure | Secrets in git or images | gen-secrets, `.gitignore`, file-based secrets | `SECRETS-GIT` |
| Information disclosure | Log shipper reads the Docker socket | Read-only socket proxy | `CT-SOCK` |
| **D**enial of service | Large bodies, slowloris | 1 MB body limit, header/body read timeouts, memory and PID limits per container | `BODY-LIMIT` |
| Denial of service | Disk fills with logs | json-file rotation, Loki retention, `HostDiskAlmostFull` alert | rules loaded (`PROM-RULES`) |
| Denial of service | Expired certificate takes the site down | Auto-renewal; `TLSCertificateExpiringSoon` alert | `TLS-EXPIRY` |
| **E**levation of privilege | Container escape via privileged mode or capabilities | No privileged containers, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, non-root users | `CT-PRIV`, `CT-NNP`, `CT-ROFS`, `CT-CAPS` |
| Elevation of privilege | Docker API abuse -> host root | Raw socket only in the proxy; proxy refuses POST/exec | `CT-SOCK` |
| Elevation of privilege | Compromised Grafana pivots to the database | Grafana is not on the `db` network | `NET-5432` and network design |

## Residual risks (accepted for the lab, listed for production)

- Single host: no high availability; RTO depends on the host coming back.
- Backup repository is on the same host in the lab.
- crm-demo's JWT secret is an environment variable (app limitation).
- Grafana admin is a local account; production should use SSO/OIDC with MFA.
- Alertmanager delivers to a local sink; production uses Telegram (commented
  example in `alertmanager/alertmanager.yml`).
- Grafana allowlist uses all private ranges; production narrows it to the VPN
  subnet.
