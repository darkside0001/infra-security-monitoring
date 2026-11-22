# ADR 0002: Network segmentation with internal Docker networks

- Status: accepted
- Date: 2026-11-22

## Context

On a single host the default Docker setup puts every container on one bridge
network where everything can reach everything, and anything with a `ports:`
entry is exposed to the Internet. A compromised Grafana or exporter should not
be able to talk to the database.

## Decision

Five networks, four of them `internal: true` (no route outside the host):

| Network | Members | Purpose |
|---------|---------|---------|
| `edge` | caddy | the only network with published ports |
| `app` (internal) | caddy, crm-api | proxy to application |
| `db` (internal) | crm-api, crm-seed, backup, db | database access |
| `mon` (internal) | caddy, prometheus, alertmanager, blackbox, node-exporter, loki, alloy, grafana, alert-sink | monitoring plane |
| `dockerapi` (internal) | alloy, docker-socket-proxy | read-only Docker API |

Fixed subnets make firewall rules and the metrics `bind` address predictable.

## Consequences

- Grafana cannot reach PostgreSQL; the database is reachable only from the API
  and the backup job.
- Verified by `verify.sh`: a scanner on the edge network cannot open
  connections to PostgreSQL, Prometheus, Loki or the API container, and a full
  TCP scan of the proxy shows only 80 and 443.
- Monitoring containers cannot reach the Internet, so Grafana plugin and
  update checks are disabled (and fail closed).
