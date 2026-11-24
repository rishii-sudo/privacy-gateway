# Privacy Gateway Architecture

**Developer:** 48sh1xbh
**Category:** Privacy verification and network security monitoring
**Target platforms:** Windows, Linux, and Kali Linux (platform-specific runtime validation is required)

## 1. Architectural principles

1. **Defensive verification:** the project provides auditing, validation, and security monitoring. It is not designed for covert surveillance, evidence destruction, or evasion of lawful attribution.
2. **Separation of concerns:** CLI/application orchestration, core verification logic, platform adapters, and parser subprocesses remain separated.
3. **Read-only discovery by default:** M2 Tor operations observe daemon state and do not change Tor configuration, host routing, firewall policy, or system proxy settings.
4. **Fail-closed status reporting:** uncertain or incomplete observations must not be reported as successful verification. The status model includes `PASS`, `FAIL`, `INCONCLUSIVE`, and `NOT_IMPLEMENTED`.
5. **Local-first operation:** logs and reports are stored locally. The application does not require a remote telemetry service.

## 2. Repository layout

```text
Privacy-Gateway/
├── cmd/gateway/                 # Go application entry point
├── configs/                     # Default YAML configuration
├── crates/pg-tor-inspector/     # Rust parser subprocess for M2
├── docs/                        # Architecture, CLI, and milestone documentation
├── internal/
│   ├── app/                     # Application lifecycle and CLI command routing
│   ├── config/                  # Configuration loading and validation
│   ├── monitor/                 # Host runtime monitoring
│   ├── network/                 # Network interface and DNS discovery
│   ├── privacy/                 # Privacy status and verification checks
│   ├── tor/                     # Tor Control Protocol client and event monitoring (M2)
│   └── ...                      # Additional foundation/planned capability packages
└── tests/                       # Test fixtures
```

The presence of a package directory does not imply that its associated future milestone is complete or production-ready.

## 3. Status model

| Status | Meaning |
|---|---|
| `PASS` | The tested requirement was satisfied. |
| `FAIL` | A verified failure or unsafe state was detected. |
| `INCONCLUSIVE` | The check could not reach a reliable conclusion. It must never be treated as `PASS`. |
| `NOT_IMPLEMENTED` | The capability is not implemented in the current release scope. |

Aggregation precedence is `FAIL`, then `INCONCLUSIVE`, then `NOT_IMPLEMENTED`; `PASS` is appropriate only when all implemented checks satisfy their requirements.

## 4. M2 Tor architecture

The Go package `internal/tor` is authoritative for the Tor Control Protocol connection, authentication, command sequencing, event demultiplexing, and state. The Rust `pg-tor-inspector` executable is an isolated parser helper using versioned JSON Lines over standard input and output. Go validates parser output before accepting it and provides a fallback parser for supported response types when the Rust helper is unavailable.

M2 supports local endpoint discovery, protocol negotiation, mandatory SAFECOOKIE authentication, Tor version and bootstrap queries, circuit/listener queries, and asynchronous `STATUS_CLIENT`, `CIRC`, and `STREAM` event monitoring. Protocol lines, aggregate responses, event queues, and parser IPC are bounded.

### M2 security boundaries

- SAFECOOKIE is mandatory. The client must not silently downgrade to weaker authentication methods.
- `SIGNAL NEWNYM` is disabled in M2.
- M2 does not edit `torrc`, configure bridges, change routes, alter firewall rules, or set system proxy configuration.
- A successful ControlPort connection does not prove that host traffic is routed through Tor. Applications need a separately configured SOCKS proxy or independently verified routing policy.
- TCP ControlPort does not provide kernel peer-credential verification. Use a supported local Unix-domain socket when kernel peer identity is a requirement.
- Configure the Rust inspector using an absolute path when it is not installed beside the gateway executable. Relative executable paths are rejected.
- Live Tor daemon behavior and native Linux peer-credential behavior must be validated on the target hosts before production use.

## 5. Milestone roadmap

- **M1 — Foundation:** Go module, configuration, status engine, host/network diagnostics, baseline privacy checks, reporting, and CLI foundation.
- **M2 — Tor Integration (current publishing scope):** read-only Tor Control Protocol monitoring, SAFECOOKIE authentication, bootstrap/circuit observation, and bounded event monitoring.
- **M3 — Network Privacy:** planned public IP, IPv6, VPN, and WebRTC verification.
- **M4 — Firewall Protection:** planned firewall adapters and controlled policy enforcement.
- **M5 — Advanced Routing:** planned routing-chain verification.
- **M6 — Tracker & Obfuscation:** planned tracker and transport verification.
- **M7 — Identity & Footprint:** planned isolation and exposure review.
- **M8 — Honeypot & Deception Lab:** planned isolated decoy research environment.
- **M9 — GUI & API Integration:** planned desktop GUI and authenticated local API.
- **M10 — Final Security Audit:** planned cross-platform and failure-injection validation.

Only capabilities implemented and tested in the current source should be described as available. Later roadmap items are not part of the M2 release claim.
