#!/bin/sh
# Disaster recovery: restore a snapshot over the live database.
#   docker compose stop crm-api
#   docker compose exec backup restore.sh [snapshot-id]    (default: latest)
#   docker compose start crm-api
set -eu
PGPASSWORD="$(cat /run/secrets/postgres_password)"
export PGPASSWORD
snapshot="${1:-latest}"

restic dump --tag postgres "$snapshot" /crm.dump > /tmp/crm.dump
pg_restore --clean --if-exists --no-owner --exit-on-error -d "$PGDATABASE" /tmp/crm.dump
rm -f /tmp/crm.dump
printf '{"event":"restore_ok","detail":"snapshot %s restored into %s"}\n' "$snapshot" "$PGDATABASE"
