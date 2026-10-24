# Contributing

Thanks for your interest. NordTail is pre-alpha. The design is still moving, so open an issue to discuss before starting on anything non-trivial.

## Ground rules

- **The guarantees in [SECURITY.md](SECURITY.md) are release gates.** A change that weakens fail-closed routing, secret handling, or tailnet-only access won't be merged, however convenient it is.
- **Tests first.** A behaviour change comes with a test that fails without it. Networking behaviour (routing, leaks, DNS) is proven by end-to-end tests, not mocks.
- **Small pull requests.** One logical change per PR, small enough to review in one pass.
- **No secrets in the repo.** Not in code, fixtures, logs, or issue text. Use obviously fake placeholder values.

## Development setup

Build, lint, and test commands will be documented here once the first code lands.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`. Write the subject in the imperative, keep it under 72 characters, and use the body to explain why.

## Pull requests

Fill in the template: what the change does, the evidence (commands run, tests added and how they failed before the change), any judgment calls, and known gaps.
