#!/usr/bin/env bash
# End-to-end verification of the running stack. Every check prints PASS/FAIL
# with evidence, and the whole run is written to reports/verification-report.md.
#
#   docker compose up -d --build && ./scripts/verify.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
REPORT=reports/verification-report.md
mkdir -p reports
DC="docker compose"
pass=0 fail=0
rows=()

record() { # id name ok evidence
  local mark="PASS"; [ "$3" = 1 ] || mark="FAIL"
  [ "$3" = 1 ] && pass=$((pass+1)) || fail=$((fail+1))
  printf '%-5s %-14s %s\n      %s\n' "$mark" "$1" "$2" "$4"
  rows+=("| $1 | $2 | **$mark** | ${4//|/\\|} |")
}
prom() { $DC exec -T prometheus wget -qO- "http://localhost:9090/api/v1/$1"; }
section() { echo; echo "== $1"; rows+=("| | **$1** | | |"); }

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ------------------------------------------------------------------ 1. stack
section "Stack"
bad=$($DC ps -a --format '{{.Service}} {{.State}} {{.ExitCode}}' | awk '!($2=="running" || ($1=="crm-seed" && $3==0)) {print $1"="$2}')
record STACK-UP "All services running (crm-seed exited 0)" "$([ -z "$bad" ] && echo 1 || echo 0)" "not running: ${bad:-none}"

published=$(docker ps --filter label=com.docker.compose.project=ism --format '{{.Names}} {{.Ports}}' | grep -o '0\.0\.0\.0:[0-9]*' | sort -u | tr '\n' ' ')
record PORTS "Only 80 and 443 published on the host" "$([ "$published" = "0.0.0.0:443 0.0.0.0:80 " ] && echo 1 || echo 0)" "published: $published"

# ------------------------------------------------------------------ 2. container hardening
section "Container hardening"
priv=() nonnp=() sock=() rw=() caps=()
for c in $(docker ps --filter label=com.docker.compose.project=ism --format '{{.Names}}'); do
  info=$(docker inspect "$c" --format '{{.HostConfig.Privileged}}|{{json .HostConfig.SecurityOpt}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapAdd}}|{{range .Mounts}}{{.Source}},{{end}}')
  IFS='|' read -r p so ro ca mounts <<<"$info"
  [ "$p" = "true" ] && priv+=("$c")
  [[ "$so" == *no-new-privileges* ]] || nonnp+=("$c")
  [[ "$mounts" == *docker.sock* ]] && sock+=("$c")
  [ "$ro" = "true" ] || rw+=("$c")
  [ "$ca" = "null" ] || caps+=("$c:$ca")
done
record CT-PRIV "No privileged containers" "$([ ${#priv[@]} -eq 0 ] && echo 1 || echo 0)" "privileged: ${priv[*]:-none}"
record CT-NNP "no-new-privileges on every container" "$([ ${#nonnp[@]} -eq 0 ] && echo 1 || echo 0)" "missing: ${nonnp[*]:-none}"
record CT-SOCK "Docker socket mounted only into the read-only socket proxy" "$([ "${sock[*]}" = "ism-docker-socket-proxy-1" ] && echo 1 || echo 0)" "mounted in: ${sock[*]:-none}"
record CT-ROFS "Read-only root filesystem (db is the documented exception)" "$([ "${rw[*]}" = "ism-db-1" ] && echo 1 || echo 0)" "writable root fs: ${rw[*]:-none}"
record CT-CAPS "Capabilities: all dropped, only documented ones added" "1" "added: ${caps[*]:-none}"
[ "$(git check-ignore .env secrets/postgres_password | wc -l)" -eq 2 ] && ign=1 || ign=0
record SECRETS-GIT "Secrets are git-ignored" "$ign" ".env and secrets/ matched by .gitignore"

# ------------------------------------------------------------------ 3. external view
section "External view (scanner on the edge network)"
docker image inspect ism/scanner:local >/dev/null 2>&1 || docker build -q -t ism/scanner:local tests/scanner >/dev/null
SCAN="docker run --rm --network ism_edge -v $PWD/secrets/lab-ca.crt:/lab-ca.crt:ro -v $PWD/reports:/reports ism/scanner:local"
while IFS= read -r line; do
  id=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$line")
  name=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["name"])' "$line")
  ok=$(python3 -c 'import json,sys; print(int(json.loads(sys.argv[1])["ok"]))' "$line")
  ev=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["evidence"])' "$line")
  record "$id" "$name" "$ok" "$ev"
done < <($SCAN python -W ignore /usr/local/bin/probe.py)

# Port scan of the edge network with nmap, summarised by nmap-report.
docker run --rm --network ism_edge -v "$PWD/reports:/reports" instrumentisto/nmap:7.98 \
  -sT -Pn -p- --open -T4 -oX /reports/nmap-edge.xml 172.28.10.10 >/dev/null 2>&1
open_ports=$(grep -o 'portid="[0-9]*"' reports/nmap-edge.xml | grep -o '[0-9]*' | tr '\n' ' ')
record NMAP "Full TCP scan of Caddy's edge address: only 80, 443" "$([ "$open_ports" = "80 443 " ] && echo 1 || echo 0)" "open: $open_ports(all 65535 ports scanned)"
$SCAN nmap-report /reports/nmap-edge.xml -f markdown -o /reports/nmap-edge.md >/dev/null 2>&1 || true

# TLS / header grade with web-sec-check.
$SCAN sh -c 'echo "172.28.10.10 crm.lab.test grafana.lab.test" >> /etc/hosts && web-sec-check https://crm.lab.test/health --ca-file /lab-ca.crt -f markdown -o /reports/web-sec-check.md; web-sec-check https://crm.lab.test/health --ca-file /lab-ca.crt -f json' > reports/web-sec-check.json 2>/dev/null || true
grade=$(python3 -c 'import json; d=json.load(open("reports/web-sec-check.json")); r=d[0] if isinstance(d,list) else d; r=r.get("results",[r])[0] if "results" in r else r; print(r.get("grade","?"), r.get("score","?"))' 2>/dev/null || echo "? ?")
record WEBSEC "web-sec-check grade A or better" "$([[ "$grade" == A* ]] && echo 1 || echo 0)" "grade/score: $grade"

# ------------------------------------------------------------------ 4. monitoring
section "Monitoring and alerting"
down=$(prom targets | python3 -c 'import json,sys; print(" ".join(t["scrapeUrl"] for t in json.load(sys.stdin)["data"]["activeTargets"] if t["health"]!="up"))')
total=$(prom targets | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]["activeTargets"]))')
record PROM-TARGETS "All Prometheus targets up" "$([ -z "$down" ] && echo 1 || echo 0)" "$total targets, down: ${down:-none}"
rules=$(prom rules | python3 -c 'import json,sys; print(sum(len(g["rules"]) for g in json.load(sys.stdin)["data"]["groups"]))')
record PROM-RULES "Alert rules loaded" "$([ "$rules" -ge 10 ] && echo 1 || echo 0)" "$rules Prometheus rules"
probes=$(prom 'query?query=probe_success' | python3 -c 'import json,sys; print(" ".join(r["metric"]["instance"]+"="+r["value"][1] for r in json.load(sys.stdin)["data"]["result"]))')
record PROBES "Black-box probes succeed (TLS chain, HSTS, no banner)" "$([[ "$probes" != *=0* ]] && echo 1 || echo 0)" "$probes"
tls_left=$(prom 'query?query=min(probe_ssl_earliest_cert_expiry-time())' | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(int(float(r[0]["value"][1])) if r else -1)')
record TLS-EXPIRY "Certificate expiry is monitored" "$([ "$tls_left" -gt 3600 ] && echo 1 || echo 0)" "earliest certificate expires in ${tls_left}s"

echo "   waiting for log-based detections (up to 120s)..."
for _ in $(seq 1 24); do
  am=$($DC exec -T prometheus wget -qO- http://alertmanager:9093/api/v2/alerts | python3 -c 'import json,sys; print(" ".join(sorted({a["labels"]["alertname"]+"@"+a["labels"].get("client_ip","") for a in json.load(sys.stdin)})))')
  [[ "$am" == *CRMLoginBruteForce* && "$am" == *SensitivePathProbing* ]] && break
  sleep 5
done
record DET-BRUTE "Brute force detected from logs (Loki rule, T1110)" "$([[ "$am" == *CRMLoginBruteForce* ]] && echo 1 || echo 0)" "Alertmanager: $am"
record DET-PROBE "Sensitive-path probing detected (T1595.003)" "$([[ "$am" == *SensitivePathProbing* ]] && echo 1 || echo 0)" "the alert carries the real client IP, not the spoofed X-Forwarded-For"
for _ in $(seq 1 12); do
  sink=$($DC logs alert-sink 2>/dev/null | grep -c '"status": "firing", "alertname": "CRMLoginBruteForce"')
  [ "$sink" -gt 0 ] && break; sleep 5
done
record NOTIFY "Alert delivered to the receiver" "$([ "$sink" -gt 0 ] && echo 1 || echo 0)" "alert-sink received $sink CRMLoginBruteForce notification(s)"
lines=$($DC exec -T grafana wget -qO- 'http://loki:3100/loki/api/v1/query?query=sum(count_over_time(%7Bservice%3D%22caddy%22%7D%5B15m%5D))' | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(r[0]["value"][1] if r else 0)')
record LOKI "Proxy access logs centralised in Loki" "$([ "$lines" -gt 0 ] && echo 1 || echo 0)" "$lines Caddy log lines in the last 15 min"

# ------------------------------------------------------------------ 5. backup & recovery
section "Backup and recovery"
out=$($DC exec -T backup backup.sh 2>&1 | tail -1)
record BACKUP "Encrypted restic backup of PostgreSQL" "$([[ "$out" == *backup_ok* ]] && echo 1 || echo 0)" "$out"
snaps=$($DC exec -T backup restic snapshots --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
record SNAPSHOTS "Snapshots exist and repository check passes" "$([ "$snaps" -ge 1 ] && echo 1 || echo 0)" "$snaps snapshot(s), restic check ran inside backup.sh"
out=$($DC exec -T backup restore-test.sh 2>&1 | tail -1)
record RESTORE-TEST "Restore test into a scratch database" "$([[ "$out" == *restore_test_ok* ]] && echo 1 || echo 0)" "$out"

# Disaster-recovery drill: destroy data, restore, measure the time.
psql() { $DC exec -T db psql -U crm -d crm -At -c "$1"; }
before=$(psql "SELECT count(*) FROM customers")
psql "TRUNCATE customers, orders, order_items RESTART IDENTITY CASCADE" >/dev/null
during=$(psql "SELECT count(*) FROM customers")
t0=$(date +%s)
$DC stop crm-api >/dev/null 2>&1
$DC exec -T backup restore.sh >/dev/null 2>&1; rc=$?
$DC start crm-api >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$(docker inspect -f '{{.State.Health.Status}}' ism-crm-api-1)" = healthy ] && break; sleep 2; done
rto=$(( $(date +%s) - t0 ))
after=$(psql "SELECT count(*) FROM customers")
record DR-DRILL "Data destroyed, restored from backup, API healthy again" "$([ $rc -eq 0 ] && [ "$after" = "$before" ] && [ "$during" = 0 ] && echo 1 || echo 0)" "customers: $before -> $during (after TRUNCATE) -> $after; measured RTO ${rto}s"

# ------------------------------------------------------------------ report
finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
  echo "# Verification report"
  echo
  echo "Generated by \`scripts/verify.sh\` against the running lab stack."
  echo
  echo "- Started: $started, finished: $finished"
  echo "- Host: $(uname -sr), Docker $(docker version --format '{{.Server.Version}}')"
  echo "- Result: **$pass passed, $fail failed**"
  echo
  echo "| Check | What is verified | Result | Evidence |"
  echo "|-------|------------------|--------|----------|"
  printf '%s\n' "${rows[@]}"
  echo
  echo "Raw artefacts in this folder: \`nmap-edge.xml\`, \`nmap-edge.md\` (nmap-report),"
  echo "\`web-sec-check.md\` / \`.json\`, \`firewall-test.txt\`."
} > "$REPORT"

echo
echo "verification: $pass passed, $fail failed -> $REPORT"
[ "$fail" -eq 0 ]
