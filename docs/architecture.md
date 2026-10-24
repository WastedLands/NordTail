# Architecture

How NordTail works today. This document follows the code: when the code changes, this changes with it.

## Overview

NordTail is one Go process (`nordtail`) running in a privileged container that has its own network namespace. It does three things:

1. **Joins your tailnet as a dashboard node** (`nordtail`), using Tailscale's embedded `tsnet` library, and serves the dashboard and its API only on that tailnet address.
2. **Builds one network namespace per region.** Each contains a WireGuard tunnel to the VPN server and its own `tailscaled`, which advertises itself as the exit node `exit-<region>`.
3. **Watches each tunnel** and takes the region's node offline while the tunnel is down.

```
container network namespace (eth0 = host network)
├─ nordtail
│   ├─ tsnet node "nordtail"  ── dashboard + API, tailnet only (HTTP :80)
│   └─ SQLite /data/nordtail.db (region configs sealed with the master key)
└─ region namespace rg-<id>                (one per region)
    ├─ veth0 10.200.N.2  ⇄  vo-<id> 10.200.N.1 in the container namespace
    ├─ wg-<id>   WireGuard to the VPN server
    └─ tailscaled (kernel mode, state in /data/regions/<id>/, UDP port 41700+N)
```

## Traffic paths in a region

| Traffic | Path |
|---|---|
| `tailscaled`'s own traffic (coordination, relays, peer connections) | main table → `veth0` → masqueraded out of the container's uplink. The region's UDP port is DNATed back in, so peers connect directly. |
| Traffic from exit-node clients (`iif tailscale0`) | policy rule → table 100 → `wg-<id>` only, masqueraded with the tunnel address |
| DNS answered by the exit node | resolver addresses routed only through `wg-<id>` |

**Fail closed.** Table 100 holds the tunnel route and an `unreachable` default behind it. If the WireGuard link goes away, the kernel deletes the tunnel route and the unreachable route takes over. IPv6 from clients always hits an unreachable route, because the tunnel doesn't carry IPv6. Each resolver route has the same unreachable fallback. Two nftables rules back this up:

- `forward`: drop anything from `tailscale0` that isn't leaving through `wg-<id>`
- `output`: drop DNS (port 53) leaving through `veth0`

The WireGuard interface is created in the container namespace and then moved into the region namespace. Its encrypted UDP socket stays in the container namespace, so tunnel traffic never depends on the region's routing.

## Tunnel health and withdrawal

Every 5 s, NordTail sends one DNS query from inside the region namespace to the region's resolver. That resolver is reachable only through the tunnel, so any answer proves the tunnel works end to end. The tunnel counts as down if the WireGuard link is down, or after 3 consecutive failed probes.

If the tunnel stays down for the grace period (`NORDTAIL_DOWN_GRACE`, default 60 s), NordTail takes the region's node offline: `tailscaled` keeps its state, identity, and route approval. Devices using that exit node then report it as offline and block traffic. Once the tunnel has been healthy for 10 s, the node comes back online.

## Dashboard access

Requests reach the dashboard only over the tailnet. For each request NordTail asks Tailscale who the caller is (`WhoIs`). It allows only identities that are a person, not a tagged device, and whose login is listed in `NORDTAIL_ADMINS`. Writes from a cross-site browser context are rejected.

## Secrets

- The master key comes from `NORDTAIL_MASTER_KEY` or `NORDTAIL_MASTER_KEY_FILE`, and NordTail refuses to start without a valid one.
- Region configs (which contain WireGuard private keys) are sealed with AES-256-GCM, bound to the region ID.
- Inside the process, secrets live in a type that prints `[redacted]` in every formatting, logging, and JSON path.
- The API reports whether a key is set, never the key itself.

## Code map

| Path | Responsibility |
|---|---|
| `cmd/nordtail` | Entry point; also the internal `netns-exec` launcher that starts `tailscaled` inside a region namespace with the region's `resolv.conf` |
| `internal/config` | Environment configuration and validation |
| `internal/secret` | Redacting secret type, master key sealing |
| `internal/store` | SQLite persistence |
| `internal/provider/wgconf` | Parser for provider-generated WireGuard configs (script hooks are ignored) |
| `internal/netns` | Region namespaces, routing, nftables (netlink and nftables libraries, no shelling out) |
| `internal/wg` | WireGuard interfaces and the tunnel probe |
| `internal/tsnode` | Per-region `tailscaled` supervision through its LocalAPI |
| `internal/controller` | Builds regions, monitors health, withdraws and restores nodes |
| `internal/web` | Dashboard and JSON API on the tailnet |
| `e2e/` | Hermetic end-to-end suite (see [CONTRIBUTING.md](../CONTRIBUTING.md)) |
