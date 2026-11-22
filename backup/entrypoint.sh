#!/bin/sh
# Runs a backup and a restore test on start, then every BACKUP_INTERVAL_SECONDS.
# A failed cycle is retried after 5 minutes instead of waiting a whole interval.
set -u
interval="${BACKUP_INTERVAL_SECONDS:-86400}"
while true; do
  if backup.sh && restore-test.sh; then
    sleep "$interval"
  else
    echo '{"event":"backup_cycle_failed","detail":"retrying in 300s"}'
    sleep 300
  fi
done
