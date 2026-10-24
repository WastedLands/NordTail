# Security

NordTail handles VPN credentials, Tailscale credentials, and the routing of all traffic you send through its exit nodes. This document states what it promises, what it does not, and how to report a problem.

> **Status: pre-alpha.** The guarantees below are design commitments. They are not yet implemented or verified. Until a release says otherwise, assume none of them hold.

## Guarantees

1. **Fail closed, including DNS.** Traffic and DNS queries from exit-node clients leave only through the VPN tunnel. If the tunnel is down, that traffic is dropped, never sent out the host's own connection. Every release is gated on automated tests that take the tunnel down and check for leaks.
2. **Plain-exit-node parity.** Tailscale's own connection traffic never goes through the VPN tunnel. An exit node performs like a plain Tailscale exit node on the same host, plus one VPN hop.
3. **Secrets stay secret.** VPN keys, Tailscale auth keys, and OAuth client secrets can be entered but are never shown back, written to logs, or returned by any API. They are encrypted at rest with a master key you provide. NordTail itself collects no telemetry and has no analytics or phone-home of its own. The third-party components it runs keep their own default behavior, which is outside NordTail's control: for example, `tailscaled` uploads its logs to Tailscale unless configured otherwise. Your VPN provider and Tailscale log according to their own policies.
4. **Tailnet-only, policy hands-off.** The dashboard has no public listener. Every request is checked against the caller's Tailscale identity. NordTail never edits your Tailscale access policy. It shows you policy snippets to paste yourself.

## What NordTail does not protect against

- **A compromised host.** The container is privileged. Anyone with root on the host can read every secret and all traffic, encrypted or not. Encryption at rest protects copies of the data volume, such as backups and snapshots, not a running host.
- **Your VPN provider or Tailscale.** You trust both, just as you would without NordTail.
- **Lost master key.** If you lose the master key, the stored secrets can't be recovered. Enter them again.
- **Policy you control.** Who in your tailnet may use an exit node or reach the dashboard is decided by your Tailscale access policy, plus NordTail's admin allowlist for the dashboard.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting on this repository: Security tab → "Report a vulnerability". Include steps to reproduce and the version or commit you tested.

There is no bug bounty. Reports are acknowledged on a best-effort basis.
