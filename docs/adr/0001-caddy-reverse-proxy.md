# ADR 0001: Caddy as the only entry point

- Status: accepted
- Date: 2026-11-22

## Context

The stack runs one public web application (crm-demo API) and one admin UI
(Grafana). Every other service (database, Prometheus, Loki, Alertmanager) must
stay private. We need TLS everywhere, sane security headers, access logs in a
machine-readable format and request metrics, with as little configuration as
possible so that mistakes are easy to spot in review.

## Options considered

| Option | For | Against |
|--------|-----|---------|
| Nginx + certbot | Very common, well known | TLS automation is a second moving part; headers and OCSP need manual tuning; access logs not JSON by default |
| Traefik | Docker-native discovery | Needs the Docker socket (or a proxy) in the edge container; labels spread config over many files |
| **Caddy** | Automatic HTTPS (ACME or internal CA), TLS 1.2+ by default, JSON logs, built-in Prometheus metrics, one short config file | Smaller community than Nginx; some modules (rate limiting) need a custom build |

## Decision

Caddy 2 is the only container with published ports (80, 443). It terminates
TLS, adds security headers once for every site, removes the `Server` banner,
caps request bodies at 1 MB, and **overwrites** `X-Forwarded-For` so a client
cannot spoof its address into the application's rate limiter or audit log.

Rate limiting stays in the application (crm-demo already does per-IP and
per-endpoint limits) instead of a custom Caddy build.

## Consequences

- One file (`caddy/Caddyfile`) describes the whole public surface.
- The metrics endpoint is bound to the monitoring network address only.
  The first run of `verify.sh` caught it listening on the edge network too
  (nmap found port 2020); fixed with `bind 172.28.40.10`.
- In production, removing `import tls_lab` switches to Let's Encrypt with no
  other change.
