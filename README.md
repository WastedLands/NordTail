# NordTail

NordTail is a self-hosted controller that turns a commercial VPN subscription into Tailscale exit nodes. Run one container on a homelab server or a cloud VPS, connect it to your tailnet and your VPN account, and pick regions. You get exit nodes like `exit-us` and `exit-uk` that you select in the normal Tailscale client on any device, with no separate VPN app. Each exit node performs like a plain exit node on that host plus one VPN hop, and its traffic can't leave outside the tunnel.

It is for self-hosters who already use Tailscale. It is not a VPN client, not a hosted service, and not affiliated with Nord Security, NordVPN, or Tailscale Inc.

## Status

**Pre-alpha. Nothing works yet.** The design is settled and the first milestone is in progress. Don't run this anywhere you care about.

Planned for the first release:

- NordVPN (NordLynx/WireGuard) with automatic server selection per country
- Any WireGuard-capable VPN provider through a pasted WireGuard config
- A dashboard reachable only over your tailnet, gated by Tailscale identity
- Tailscale SaaS, with auth keys or an OAuth client
- `linux/amd64` and `linux/arm64` container images

## Requirements

- A Linux host (bare metal or a KVM virtual machine) with Docker. Docker Desktop on macOS or Windows, and container-based VPSes (OpenVZ, LXC), are not supported.
- A Tailscale tailnet.
- A NordVPN subscription, or another provider that offers WireGuard configs.

## Security

See [SECURITY.md](SECURITY.md) for what NordTail promises, what it doesn't, and how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
