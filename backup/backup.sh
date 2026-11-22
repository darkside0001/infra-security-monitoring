#!/bin/sh
# Encrypted, deduplicated PostgreSQL backup with restic.
# Writes Prometheus metrics for node-exporter's textfile collector.
set -eu

PGPASSWORD="$(cat /run/secrets/postgres_password)"
export PGPASSWORD
METRICS=/textfile/backup.prom

log() { printf '{"event":"%s","detail":"%s"}\n' "$1" "${2:-}"; }

write_metric() {
  # $1 = name, $2 = value. Atomic replace so node-exporter never reads half a file.
  tmp="$(mktemp /textfile/.backup.XXXXXX)"
  { grep -v "^$1 " "$METRICS" 2>/dev/null || true; echo "$1 $2"; } > "$tmp"
  chmod 0644 "$tmp"
  mv "$tmp" "$METRICS"
}

if ! restic cat config >/dev/null 2>&1; then
  restic init
  log repo_initialized "$RESTIC_REPOSITORY"
fi

start=$(date +%s)
# --stdin-from-command: if pg_dump exits non-zero, restic does NOT save a
# snapshot. A plain `pg_dump | restic backup --stdin` would happily store a
# truncated dump and report success.
restic backup --quiet --tag postgres --host ism-backup \
  --stdin-filename crm.dump --stdin-from-command -- \
  pg_dump --format=custom --no-owner --dbname="$PGDATABASE"

restic forget --quiet --tag postgres --host ism-backup \
  --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
restic check --quiet

end=$(date +%s)
size=$(restic stats latest --json --mode restore-size | sed -n 's/.*"total_size":\([0-9]*\).*/\1/p')
write_metric backup_last_success_timestamp_seconds "$end"
write_metric backup_duration_seconds "$((end - start))"
write_metric backup_last_size_bytes "${size:-0}"
log backup_ok "duration=$((end - start))s size=${size:-0}B"
