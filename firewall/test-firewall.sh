#!/usr/bin/env bash
# Tests firewall/nftables.conf for real instead of only checking its syntax.
#
# Starts a "server" container with its own network namespace, loads the
# ruleset there (NET_ADMIN only inside that namespace, the host is not
# touched), opens listeners on several ports and scans it from an "admin"
# address and an "outsider" address.
set -euo pipefail
cd "$(dirname "$0")"
NET=ism-fwtest
SERVER=172.31.99.2 ADMIN=172.31.99.10 OUTSIDER=172.31.99.20
pass=0 fail=0

cleanup() { docker rm -f fw-server fw-admin fw-outsider >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create --subnet 172.31.99.0/24 $NET >/dev/null
docker image inspect ism/fwtest:local >/dev/null 2>&1 || docker build -q -t ism/fwtest:local -f Dockerfile.test . >/dev/null

# Same ruleset, admin network pointed at the test "admin" container.
tmp="$(mktemp -d)"
cp nftables.conf "$tmp/nftables.conf"
echo "define ADMIN_NET = { $ADMIN/32 }" > "$tmp/admin-net.nft"
sed -i "s#/etc/nftables.d/admin-net.nft#/fw/admin-net.nft#" "$tmp/nftables.conf"

docker run -d --name fw-server --network $NET --ip $SERVER --cap-add NET_ADMIN \
  -v "$tmp:/fw:ro" ism/fwtest:local sleep 600 >/dev/null
# One TCP listener per port, all in one small Python process.
docker exec -d fw-server python3 -c '
import socket, threading
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(64)
    while True:
        c, _ = s.accept(); c.close()
for p in (22, 80, 443, 5432, 9090, 2375):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
'
docker exec fw-server nft -c -f /fw/nftables.conf
docker exec fw-server nft -f /fw/nftables.conf
echo "ruleset loaded:"; docker exec fw-server nft list table inet host_firewall | sed -n '1,12p'

docker run -d --name fw-admin --network $NET --ip $ADMIN ism/fwtest:local sleep 600 >/dev/null
docker run -d --name fw-outsider --network $NET --ip $OUTSIDER ism/fwtest:local sleep 600 >/dev/null
sleep 1

probe() { # client port -> exit 0 if a TCP connection succeeds within 2s
  docker exec "$1" python3 -c "import socket,sys; socket.create_connection(('$SERVER', $2), timeout=2)" 2>/dev/null
}
expect() { # client port open|closed
  if probe "$1" "$2"; then got=open; else got=closed; fi
  if [ "$got" = "$3" ]; then echo "PASS  $1 -> :$2 $got"; pass=$((pass+1)); else echo "FAIL  $1 -> :$2 expected $3, got $got"; fail=$((fail+1)); fi
}
expect fw-outsider 80 open
expect fw-outsider 443 open
expect fw-outsider 22 closed
expect fw-outsider 5432 closed
expect fw-outsider 9090 closed
expect fw-outsider 2375 closed
expect fw-admin 22 open
expect fw-admin 5432 closed

# SSH flood from the admin address: more than 10 new connections/minute
# puts it in the ssh_offenders set.
for _ in $(seq 1 15); do probe fw-admin 22 || true; done
if docker exec fw-server nft list set inet host_firewall ssh_offenders | grep -q "$ADMIN"; then
  echo "PASS  SSH rate limit: $ADMIN added to ssh_offenders after 15 connections"; pass=$((pass+1))
else
  echo "FAIL  SSH rate limit did not trigger"; fail=$((fail+1))
fi
expect fw-admin 22 closed

echo "firewall tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
