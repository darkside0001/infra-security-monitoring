# ADR 0005: Encrypted backups with restic, and restore tests that run by themselves

- Status: accepted
- Date: 2026-11-22

## Context

A backup that has never been restored is a hope, not a backup. Requirements:
encrypted at rest, deduplicated, retention policy, monitored, and regularly
proven restorable without a human.

## Decision

- `pg_dump --format=custom` streamed into **restic** with
  `--stdin-from-command`. If `pg_dump` fails, restic does not save a snapshot.
  (A plain `pg_dump | restic backup --stdin` stores a truncated dump and
  reports success.)
- Retention: 7 daily, 4 weekly, 6 monthly; `restic check` after every run.
- After every backup, `restore-test.sh` restores the latest snapshot into a
  scratch database and compares row counts table by table with the live one.
- Both write metrics for node-exporter's textfile collector; Prometheus alerts
  on `BackupTooOld` (> 26 h), `BackupMissing` and `RestoreTestFailed`.
- The backup container runs as the `postgres` user with all capabilities
  dropped and a read-only root filesystem.

Targets for this lab: **RPO 24 h** (daily backup), **RTO under 5 minutes**.
The disaster-recovery drill in `verify.sh` truncates the customer and order
tables, restores the latest snapshot and waits for the API health check:
measured RTO 34 s, most of it the health-check interval.

## Consequences

- The lab keeps the restic repository in a Docker volume. In production it
  goes off the host (S3/B2/SFTP: change `RESTIC_REPOSITORY`), ideally with
  append-only credentials so a compromised host cannot delete old snapshots.
- Losing `secrets/restic_password` makes every backup unreadable; store it in
  a password manager, separately from the server.
