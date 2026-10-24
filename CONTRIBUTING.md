# Contributing

Thanks for your interest. NordTail is pre-alpha. The design is still moving, so open an issue to discuss before starting on anything non-trivial.

## Ground rules

- **The guarantees in [SECURITY.md](SECURITY.md) are release gates.** A change that weakens fail-closed routing, secret handling, or tailnet-only access won't be merged, however convenient it is.
- **Tests first.** A behaviour change comes with a test that fails without it. Networking behaviour (routing, leaks, DNS) is proven by end-to-end tests, not mocks.
- **Small pull requests.** One logical change per PR, small enough to review in one pass.
- **No secrets in the repo.** Not in code, fixtures, logs, or issue text. Use obviously fake placeholder values.

## Development setup

You need Linux, Go (the version in `go.mod`), and Docker with Compose. The end-to-end suite runs privileged containers.

```bash
gofmt -l .                       # must print nothing
go vet ./... && go vet -tags e2e ./e2e
go test -count=1 ./...           # unit and integration tests: no network, no credentials
make e2e                         # hermetic end-to-end suite (about 4 minutes)
make e2e-keep                    # same, but leave the environment running for debugging
docker build -t nordtail:dev .   # container image
```

`make e2e` runs everything in Docker Compose (`e2e/compose.yaml`):

- **Headscale**, a test-only coordination server
- **Tailscale's `derper`**, as relay and STUN server
- **a WireGuard "fake VPN"**
- **an echo service** standing in for the internet: it reports the source address of every request
- **two tailnet clients**
- **NordTail** itself

The suite checks where traffic and DNS actually come out, including with the tunnel down, and writes `e2e/out/report.json`. It needs no accounts or secrets. Read [docs/architecture.md](docs/architecture.md) before changing routing, the firewall, or the dashboard boundary.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`. Write the subject in the imperative, keep it under 72 characters, and use the body to explain why.

## Pull requests

Fill in the template: what the change does, the evidence (commands run, tests added and how they failed before the change), any judgment calls, and known gaps.
