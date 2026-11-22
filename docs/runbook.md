# Runbook

One section per alert. Each says what it means, how to confirm it and what to do.
Commands assume the repository directory on the host.

## ScrapeTargetDown
A service stopped exposing metrics.
- Confirm: `docker compose ps` and `docker compose logs --tail 50 <service>`.
- Fix: `docker compose up -d <service>`. If it crash-loops, check the last config change (`git log -p <service>/`).

## EndpointDown
The black-box probe failed: site down, TLS chain invalid, HSTS missing or a `Server` banner came back.
- Confirm: `docker compose exec prometheus wget -qO- 'http://blackbox:9115/probe?module=https_2xx&target=https://crm.lab.test/health&debug=true'`.
- The debug output names the failing step (connection, TLS, status code or header).

## High5xxRate
More than 5% of requests to a host fail.
- Confirm in Grafana: "Requests/s by status"; logs: `{service="caddy", status_class="5xx"}`.
- Typical causes: API container unhealthy, database down, migration error. Check `docker compose logs crm-api`.

## TLSCertificateExpiringSoon
Renewal is failing.
- Confirm: `docker compose logs caddy | grep -i -E "tls|acme|certificate"`.
- Production: check DNS points at the host and port 80 is reachable (HTTP-01 challenge).

## UnexpectedAuthFailures
Sustained 401/403/429 at the proxy. Often precedes or accompanies CRMLoginBruteForce.

## CRMLoginBruteForce
MITRE ATT&CK T1110. One client IP failed or was throttled on `/api/v1/auth/login` more than 10 times in 5 minutes.
1. Identify: Grafana panel "Failed CRM logins per client IP", or LogQL
   `{service="caddy"} | json uri="request.uri", ip="request.client_ip" | uri="/api/v1/auth/login"`.
2. Check whether any login from that IP **succeeded** (status 200) — if yes, treat the account as compromised: revoke its sessions in the CRM, reset the password, review the audit log.
3. Block the source if it continues: `nft add element inet host_firewall ssh_offenders { <ip> }` is for SSH; for web add a Caddy `remote_ip` matcher or block at the provider firewall.
4. Record the incident (time, IP, accounts targeted, outcome).

## SensitivePathProbing
MITRE ATT&CK T1595.003. Automated scanning for `/.env`, `/.git`, admin panels. Usually noise from the Internet; act only if any of those requests returned 200.

## BackupMissing / BackupTooOld
- Confirm: `docker compose logs --tail 20 backup`.
- Run manually: `docker compose exec backup backup.sh`.
- Common causes: database unreachable, repository full, wrong restic password.

## RestoreTestFailed
The latest backup could not be restored or its row counts differ. **Treat as high priority**: until fixed, there may be no usable backup.
- Run: `docker compose exec backup restore-test.sh` and read the JSON `detail`.
- If the repository is damaged: `docker compose exec backup restic check --read-data`.

## Disaster recovery: restore the database
```bash
docker compose stop crm-api
docker compose exec backup restic snapshots          # pick one, or use latest
docker compose exec backup restore.sh [snapshot-id]
docker compose start crm-api
./scripts/verify.sh                                  # confirm everything is green
```
Measured in the lab: 34 s from start of restore to healthy API.

## HostDiskAlmostFull / HostMemoryPressure
- `docker system df`, `du -sh /var/lib/docker/volumes/*`.
- Loki retention is 30 days, Prometheus 15 days; container logs rotate at 3 x 10 MB.
