#!/usr/bin/env bash
# Restricts traffic that Docker forwards to containers (published ports).
# Docker evaluates the DOCKER-USER chain before its own rules, and keeps it
# across restarts. Run at boot after Docker starts (systemd unit in the README).
#
#   EXT_IF=eth0 ./firewall/docker-user.sh
set -euo pipefail
EXT_IF="${EXT_IF:?set EXT_IF to the public interface, e.g. eth0}"

iptables -N DOCKER-USER 2>/dev/null || true
iptables -F DOCKER-USER
# Replies to connections that containers opened.
iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
# Traffic not coming from the Internet (container to container, host to container).
iptables -A DOCKER-USER ! -i "$EXT_IF" -j RETURN
# From the Internet: only the original destination ports 80 and 443.
iptables -A DOCKER-USER -p tcp -m conntrack --ctorigdstport 80 --ctdir ORIGINAL -j RETURN
iptables -A DOCKER-USER -p tcp -m conntrack --ctorigdstport 443 --ctdir ORIGINAL -j RETURN
iptables -A DOCKER-USER -m limit --limit 5/min -j LOG --log-prefix "docker-user-drop: "
iptables -A DOCKER-USER -j DROP
iptables -S DOCKER-USER
