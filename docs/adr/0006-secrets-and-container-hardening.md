# ADR 0006: Secrets handling and container hardening baseline

- Status: accepted
- Date: 2026-11-22

## Decision

**Secrets**
- Generated locally by `scripts/gen-secrets.sh` (random, 32+ bytes), never
  committed: `.env` and `secrets/` are git-ignored, checked by `verify.sh`.
- Passed as files (`*_FILE` variables, Compose secrets) wherever the image
  supports it: PostgreSQL, Grafana, restic. crm-demo reads environment
  variables only, so its JWT secret comes from `.env` (known limitation:
  visible to anyone who can run `docker inspect`, which already means root).
- The lab CA private key is readable only by Caddy; other containers get the
  public certificate.

**Every container**
- `no-new-privileges`, `cap_drop: [ALL]`, read-only root filesystem with
  `tmpfs` for scratch space, memory and PID limits, log rotation
  (3 x 10 MB).
- Non-root users wherever the image allows it.
- Documented exceptions: Caddy keeps `NET_BIND_SERVICE` (ports 80/443);
  PostgreSQL's entrypoint needs `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`,
  `FOWNER` and a writable root to initialise and then drops to `postgres`.
- Images pinned to explicit versions; the application image is built from a
  pinned git commit of crm-demo.

**Admin access**
- Grafana: login required (anonymous, sign-up and basic auth off), secure
  SameSite=strict cookies, 1 h idle timeout, reachable only from private
  address ranges at the proxy. Prometheus, Alertmanager and Loki have no
  route from outside at all.
