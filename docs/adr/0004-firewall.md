# ADR 0004: Host firewall that coexists with Docker

- Status: accepted
- Date: 2026-11-22

## Context

A common mistake: a default-drop nftables/ufw INPUT policy is assumed to
protect containers too. It does not. Traffic to a published container port is
DNATed in PREROUTING and goes through the FORWARD chain, so INPUT rules never
see it. And `flush ruleset` in `/etc/nftables.conf` deletes the rules Docker
created, cutting containers off the network.

## Decision

1. `firewall/nftables.conf` owns only its own table (`inet host_firewall`):
   default-drop INPUT, SSH only from the admin VPN subnet with a dynamic
   blocklist for clients that open more than 10 connections a minute,
   WireGuard, 80/443, rate-limited logging of drops. No `flush ruleset`.
2. `firewall/docker-user.sh` fills Docker's `DOCKER-USER` chain: from the
   public interface only original destination ports 80 and 443 are forwarded
   to containers.
3. Only Caddy has `ports:` in Compose, and `verify.sh` fails if anything else
   is published.

## Verification

`firewall/test-firewall.sh` loads the real ruleset into a throwaway network
namespace (a container with `NET_ADMIN`, the host is not touched), opens
listeners on 22, 80, 443, 5432, 9090 and 2375, and connects from an "admin"
and an "outsider" address. Result in `reports/firewall-test.txt` (10/10),
including the SSH rate limit putting the admin address in `ssh_offenders`.
