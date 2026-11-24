# Privacy Gateway

**Privacy Gateway** is a Go-based privacy verification and network security monitoring project. It is being developed as a defensive, local-first tool for inspecting host and network privacy posture.

> **Project status:** Early development. The `main` branch currently contains the M1 foundation. M2 Tor integration is being developed separately in [`milestone/m2-tor-integration`](https://github.com/rishii-sudo/privacy-gateway/tree/milestone/m2-tor-integration) and tracked in [Draft PR #1](https://github.com/rishii-sudo/privacy-gateway/pull/1). M2 has not been merged into `main` and is not presented as a production-ready release.

## What it aims to do

Privacy Gateway follows a defensive verification model:

- Inspect host and network state using read-only discovery by default.
- Run implemented privacy checks and report explicit outcomes.
- Distinguish verified results from inconclusive or not-yet-implemented checks.
- Keep diagnostics, logs, and reports local by default.
- Provide a command-line interface and machine-readable reporting.

## Current scope: M1 foundation

The current `main` branch includes the project foundation:

- Go application and CLI startup
- YAML configuration loading and validation
- Host and runtime diagnostics
- Read-only network interface and DNS discovery
- Baseline privacy verification and status aggregation
- Terminal and JSON reporting
- Structured local logging

### Verification states

Checks use explicit states rather than treating missing evidence as success:

| State | Meaning |
| --- | --- |
| `PASS` | The implemented check satisfied its requirement. |
| `FAIL` | A verified issue or unprotected state was detected. |
| `INCONCLUSIVE` | The check could not reach a reliable conclusion. |
| `NOT_IMPLEMENTED` | The capability is planned but not implemented in the current scope. |

## Development roadmap

The broader project roadmap includes:

- **M1 — Foundation:** configuration, status engine, host/network diagnostics, baseline checks, CLI and reporting.
- **M2 — Tor integration:** Control Protocol monitoring, SAFECOOKIE authentication, bootstrap and circuit observation. Currently in a separate draft pull request; not merged into `main`.
- **M3 — Network privacy:** public IP verification, IPv6 leak detection, VPN tunnel monitoring and WebRTC checks.
- **M4 — Firewall protection:** platform firewall adapters and carefully controlled protection policies.
- **M5 — Advanced routing:** routing-chain and exit-node verification.
- **M6 — Tracker and obfuscation:** tracker filtering and transport/bridge validation.
- **M7 — Identity and footprint:** environment separation and exposure review.
- **M8 — Honeypot lab:** isolated research decoys and local event recording.
- **M9 — GUI and API integration:** desktop interface and authenticated local API.
- **M10 — Final security audit:** cross-platform testing, failure injection and release preparation.

Roadmap items are plans, not claims that those features are currently available.

## Security and privacy boundaries

- The project is intended for authorized defensive testing and privacy verification.
- Discovery is read-only by default; do not assume every planned capability is implemented.
- No telemetry or remote reporting is intended by default.
- Do not expose local administrative or control interfaces to untrusted networks.
- A successful local diagnostic does not prove that all system traffic is protected or routed through a privacy network.
- Review the current implementation and configuration before using it on a production system.

For vulnerability reporting and security expectations, see [SECURITY.md](SECURITY.md) when available in the relevant development branch.

## Requirements

- Go **1.26.5** (as declared in `go.mod`)
- Git

Additional toolchains or local services may be required for capabilities developed in later milestones.

## Build from source

```bash
git clone https://github.com/rishii-sudo/privacy-gateway.git
cd privacy-gateway

go test ./...
go vet ./...
go build -o privacy-gateway ./cmd/gateway
```

On Windows, build with:

```powershell
go build -o privacy-gateway.exe ./cmd/gateway
```

## CLI

The M1 command reference documents these entry points:

```bash
privacy-gateway --help
privacy-gateway --version
privacy-gateway --diagnostics
privacy-gateway --cli

privacy-gateway status
privacy-gateway check
privacy-gateway check --json
privacy-gateway report
privacy-gateway report --json
privacy-gateway diagnostics
```

See [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) for usage details and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design principles and the roadmap.

## Repository layout

```text
cmd/gateway/       Application entry point
configs/           Default configuration
internal/          Application, monitoring, privacy and platform logic
docs/              Architecture and CLI documentation
tests/fixtures/    Test fixtures
Logs/              Local runtime log location
Reports/           Local report location
```

## Contributing

The project is under active development. Before proposing changes:

1. Check the current milestone and open pull requests.
2. Keep security boundaries and read-only defaults explicit.
3. Add tests for behavior changes and failure cases.
4. Do not commit credentials, cookie files, private keys, local reports, logs, or build artifacts.
5. Avoid describing planned or unverified functionality as complete.

## License

MIT. See [LICENSE](LICENSE).
