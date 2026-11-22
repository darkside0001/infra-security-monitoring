#!/bin/sh
# Proves the latest backup can actually be restored: restores it into a
# throwaway database and compares row counts with the live database.
set -eu

PGPASSWORD="$(cat /run/secrets/postgres_password)"
export PGPASSWORD
METRICS=/textfile/backup.prom
TEST_DB=restore_check

write_metric() {
  tmp="$(mktemp /textfile/.backup.XXXXXX)"
  { grep -v "^$1 " "$METRICS" 2>/dev/null || true; echo "$1 $2"; } > "$tmp"
  chmod 0644 "$tmp"
  mv "$tmp" "$METRICS"
}

fail() {
  write_metric backup_restore_test_success 0
  printf '{"event":"restore_test_failed","detail":"%s"}\n' "$1"
  psql -q -d postgres -c "DROP DATABASE IF EXISTS $TEST_DB" >/dev/null 2>&1 || true
  exit 1
}

counts() {
  # One line per table: "<table> <rows>", sorted, for a stable diff.
  psql -At -d "$1" -c "SELECT format('SELECT %L || '' '' || count(*) FROM %I.%I', tablename, schemaname, tablename)
                       FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename" \
    | while read -r q; do psql -At -d "$1" -c "$q"; done
}

start=$(date +%s)
psql -q -d postgres -c "DROP DATABASE IF EXISTS $TEST_DB" >/dev/null
psql -q -d postgres -c "CREATE DATABASE $TEST_DB" >/dev/null

restic dump --tag postgres latest /crm.dump > /tmp/crm.dump || fail "restic dump"
pg_restore --no-owner --exit-on-error -d "$TEST_DB" /tmp/crm.dump || fail "pg_restore"
rm -f /tmp/crm.dump

live="$(counts "$PGDATABASE")"
restored="$(counts "$TEST_DB")"
[ -n "$restored" ] || fail "no tables restored"
# The lab database is quiet between backup and test. On a busy database,
# compare with counts captured at dump time instead.
[ "$live" = "$restored" ] || fail "row counts differ: live=[$live] restored=[$restored]"

psql -q -d postgres -c "DROP DATABASE $TEST_DB" >/dev/null
end=$(date +%s)
write_metric backup_restore_test_success 1
write_metric backup_restore_test_timestamp_seconds "$end"
write_metric backup_restore_test_duration_seconds "$((end - start))"
tables=$(echo "$restored" | wc -l | tr -d ' ')
printf '{"event":"restore_test_ok","detail":"%s tables, row counts match, %ss"}\n' "$tables" "$((end - start))"
