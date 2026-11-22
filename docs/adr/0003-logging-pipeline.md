# ADR 0003: Centralised logs with Alloy and Loki, through a socket proxy

- Status: accepted
- Date: 2026-11-22

## Context

Logs from every container must land in one searchable place, and security
detections must be possible on them (for example brute force against the CRM
login, where only the proxy log has the real client IP).

Reading container logs needs the Docker API. Mounting `/var/run/docker.sock`
into a log shipper is equivalent to giving it root on the host: the API can
start a privileged container that mounts `/`.

## Options considered

- Docker `loki` logging driver: needs a plugin installed on the host, and log
  delivery problems can block containers.
- Shipper with the raw socket mounted: simplest, but root-equivalent.
- **Shipper behind a read-only socket proxy**: one more container, no write
  access to the Docker API.

## Decision

Grafana Alloy (Promtail's successor) discovers containers and reads their logs
through `tecnativa/docker-socket-proxy`, configured to allow only `GET` on
containers, networks, events, info and version. `POST`, `exec`, images and
volumes are refused. The proxy sits alone with Alloy on an internal network.

Loki stores 30 days of logs and runs a ruler for log-based alerts
(`loki/rules/fake/rules.yml`): CRM login brute force (T1110) and sensitive-path
probing (T1595.003), keyed by the client IP from Caddy's JSON access log.

## Consequences

- `verify.sh` checks that the socket is mounted in the proxy and nowhere else.
- Status class (2xx/4xx/5xx) is a Loki label; client IP stays in the log line
  to avoid a high-cardinality label.
