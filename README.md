# Privacy Gateway

**Privacy Gateway** is a Go-based privacy verification and network security monitoring project. The current repository scope includes the M1 foundation and an M2 Tor Control Protocol monitoring implementation. The project is intended for authorized local testing and defensive verification.

> **Development status:** M2 is under active development. The source includes later milestone package scaffolding, but those packages must not be interpreted as completed or production-ready features. Live Tor daemon and native Linux validation remain outstanding.

## Current capabilities

### M1 foundation

- Configuration loading and validation
- Host and network interface diagnostics
- Baseline privacy check/status aggregation
- CLI and JSON reporting
- Local logging and report output

### M2 Tor monitoring

- Local Tor ControlPort endpoint discovery
- Tor Control Protocol negotiation
- Mandatory SAFECOOKIE authentication; no silent downgrade
- Tor version, bootstrap, circuit and SOCKS listener queries
- Asynchronous `STATUS_CLIENT`, `CIRC`, and `STREAM` event monitoring
- Bounded protocol messages, event queues, and Go/Rust parser IPC
- Rust `pg-tor-inspector` parser subprocess with Go-side response validation and fallback parsing
- Explicit degraded/inconclusive states when monitoring cannot be trusted

## M2 security boundaries

M2 is read-only monitoring, not a Tor configuration manager or traffic-routing product.

- Does not edit `torrc` or configure bridges
- Does not change routes, firewall rules, or system proxy settings
- Does not transparently route host traffic through Tor
- `SIGNAL NEWNYM` is intentionally disabled
- SAFECOOKIE is required; authentication downgrade is prohibited
- TCP ControlPort does not provide kernel peer-credential verification; use a supported local Unix socket when that assurance is required

A successful ControlPort connection does **not** prove that all host traffic is using Tor. Applications must independently configure a SOCKS proxy or use a separately verified routing policy.

## Repository layout

```text
cmd/gateway/                 Go CLI entry point
configs/                     Default YAML configuration
crates/pg-tor-inspector/     Rust parser subprocess
internal/tor/                Tor Control Protocol client and monitoring
internal/app/                Application and CLI command integration
internal/                     Other foundation and planned capability packages
docs/                        Architecture and CLI documentation
tests/                       Test fixtures
```

## Requirements

- Go **1.26.5** (as declared in `go.mod`)
- Rust stable toolchain with Cargo (to build the optional Rust inspector)
- A Tor daemon with a locally configured ControlPort for live M2 operation

The Rust inspector is an optional parser helper; when it is unavailable, the Go fallback parser is used for supported response types. For a hardened deployment, install the inspector in a trusted location and configure its **absolute path**.

## Build

### Go application

```bash
git clone https://github.com/rishii-sudo/privacy-gateway.git
cd privacy-gateway
go test ./...
go vet ./...
go build -o privacy-gateway ./cmd/gateway
```

### Rust inspector

```bash
cd crates/pg-tor-inspector
cargo fmt --check
cargo test
cargo build --release
```

The Rust binary is produced under `target/release/` (or `target/release/pg-tor-inspector.exe` on Windows). Configure `tor.inspector_path` in the YAML configuration with the absolute path to the built binary, or place the companion binary beside the gateway executable.

## Configuration

Start from [`configs/default.yaml`](configs/default.yaml). Tor integration is disabled by default. Before enabling it, configure a local Tor ControlPort and a SAFECOOKIE authentication cookie file according to the Tor daemon's own documentation and your operating system's permissions.

Relevant settings:

```yaml
tor:
  enabled: false
  control_endpoint: "127.0.0.1:9051"
  network_mode: "tcp"
  connection_timeout: 5s
  auth_preference: "safecookie"
  cookie_path: ""
  event_subscriptions:
    - "STATUS_CLIENT"
    - "CIRC"
    - "STREAM"
  event_queue_limit: 1000
  inspector_path: "pg-tor-inspector"
  inspector_timeout: 2s
```

Do not expose a Tor ControlPort to untrusted networks. Protect the cookie file and keep it readable only by the account running the gateway. For TCP ControlPort, SAFECOOKIE protects the authentication exchange but does not provide local kernel peer identity.

## CLI usage

```bash
privacy-gateway --help
privacy-gateway status
privacy-gateway check
privacy-gateway diagnostics
privacy-gateway tor status
privacy-gateway tor bootstrap
privacy-gateway tor circuits
privacy-gateway tor events 30s
privacy-gateway tor diagnostics
```

See [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) for the command reference and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for architecture and security boundaries.

## Validation status

The project includes Go unit and integration-style tests and Rust parser tests. A live Tor daemon is not required for the ordinary unit test suite. Live daemon authentication, native Linux peer-credential checks, and cross-platform runtime behavior must be tested on the corresponding hosts before production use. Do not treat cross-compilation alone as runtime validation.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
