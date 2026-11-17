# Architecture Documentation â€” Privacy Gateway

**Developer:** 48sh1xbh
**Category:** Privacy Verification, Network Security Monitoring and Privacy Management Platform
**Target Platforms:** Windows, Linux, Kali Linux

---

## 1. Architectural Philosophy & Principles

Privacy Gateway is designed as a legitimate privacy engineering and authorized security research platform. The system adheres to strict engineering principles:

1. **Defensive Verification, Not Deception**: Privacy Gateway provides auditing, validation, and defensive fail-closed controls. It does not provide covert surveillance, evidence destruction, or evasion of lawful attribution.
2. **Strict Separation of Concerns**: Clear structural separation between CLI interaction, internal core logic, platform adapters (WFP/nftables), GUI representation, and local API servers.
3. **Read-Only Discovery by Default**: System and network discovery operations query the operating system in a strictly read-only manner, emitting zero unsolicited network packets during enumeration.
4. **Fail-Closed Security Posture**: Security boundaries (such as the kill switch scheduled for Milestone 4) default to a closed state, requiring explicit administrative approval before applying any system modifications.
5. **No Telemetry by Default**: All logs, diagnostics, and reports remain local to the user's filesystem in the `Logs/` and `Reports/` directories. No background data collection or remote transmission exists.

---

## 2. Directory Layout

```
Privacy-Gateway/
â”œâ”€â”€ cmd/
â”‚   â””â”€â”€ gateway/                 # Main binary entrypoint & argument dispatch
â”œâ”€â”€ internal/
â”‚   â”œâ”€â”€ app/                     # Application lifecycle, CLI shells, and command routers
â”‚   â”œâ”€â”€ api/                     # Local Go authenticated API server (M9)
â”‚   â”œâ”€â”€ config/                  # Safe YAML configuration management & validation
â”‚   â”œâ”€â”€ monitor/                 # Host runtime, OS, architecture, and memory monitoring
â”‚   â”œâ”€â”€ privacy/                 # Status engine, check results, and baseline privacy tests
â”‚   â”œâ”€â”€ network/                 # Read-only network interface enumeration & DNS discovery
â”‚   â”œâ”€â”€ tor/                     # Tor Control Protocol controller & circuit tracker (M2)
â”‚   â”œâ”€â”€ vpn/                     # VPN interface discovery & tunnel verification (M3)
â”‚   â”œâ”€â”€ routing/                 # Multi-hop routing chain validation (M5)
â”‚   â”œâ”€â”€ firewall/                # Operating system firewall abstraction & kill switch (M4)
â”‚   â”‚   â”œâ”€â”€ linux/               # Linux nftables adapter
â”‚   â”‚   â””â”€â”€ windows/             # Windows Filtering Platform (WFP) adapter
â”‚   â”œâ”€â”€ tracker/                 # System-wide and browser tracker mitigation (M6)
â”‚   â”œâ”€â”€ obfuscation/             # Transport disguise (obfs4, bridges) verification (M6)
â”‚   â”œâ”€â”€ isolation/               # Personal vs research environment separation (M7)
â”‚   â”œâ”€â”€ footprint/               # Legitimate digital footprint & exposure auditing (M7)
â”‚   â”œâ”€â”€ deception/               # Isolated research honeypot decoys (M8)
â”‚   â”œâ”€â”€ logging/                 # Structured local logging, redaction & recycle bin
â”‚   â”œâ”€â”€ report/                  # Terminal and JSON security audit report generator
â”‚   â”œâ”€â”€ audit/                   # Immutable security audit log engine (M10)
â”‚   â””â”€â”€ authorization/           # Fine-grained operational policy enforcement (M9)
â”œâ”€â”€ frontend/
â”‚   â””â”€â”€ src/                     # React/TypeScript desktop GUI (M9)
â”œâ”€â”€ configs/
â”‚   â””â”€â”€ default.yaml             # Production baseline configuration
â”œâ”€â”€ tests/
â”‚   â””â”€â”€ fixtures/                # Configuration and test fixtures
â”œâ”€â”€ docs/                        # Architecture, specifications, and CLI documentation
â”œâ”€â”€ Logs/                        # Active runtime log storage
â”œâ”€â”€ Reports/                     # Saved audit and verification reports
â”œâ”€â”€ Recycle Bin/                 # Archived logs with user-controlled recovery
â””â”€â”€ Backups/                     # Configuration and state backups
```

---

## 3. Strongly Typed Status Engine

The status engine defines four verification states:

| Status | Meaning |
| :--- | :--- |
| **`PASS`** | The tested privacy or security requirement was completely satisfied. |
| **`FAIL`** | A verified security vulnerability, privacy leak, or unprotected state was detected. |
| **`INCONCLUSIVE`** | The check could not reach a definitive conclusion (e.g., endpoint timed out or state is ambiguous). Never reported as `PASS`. |
| **`NOT_IMPLEMENTED`** | The capability belongs to a planned future milestone and is not yet available. |

### Status Precedence (Aggregation Rules)
When aggregating multiple verification results into an overall score:
1. If **any** check is `FAIL`, the overall status is **`FAIL`**.
2. If no check failed, but at least one check is `INCONCLUSIVE`, the overall status is **`INCONCLUSIVE`**.
3. If all checks are `NOT_IMPLEMENTED`, the overall status is **`NOT_IMPLEMENTED`**.
4. Only when all implemented checks satisfy requirements does the status become **`PASS`**.

---

## 4. Milestone Roadmap

- **M1 â€” Foundation (Current)**: Go module initialization, architecture, configuration management, status engine, system monitoring, read-only network enumeration, baseline privacy checks, terminal/JSON reporting, and CLI startup interface.
- **M2 â€” Tor Integration**: Native Tor Control Protocol integration, bootstrap tracking, circuit observation, and bridge configuration.
- **M3 â€” Network Privacy**: Multi-endpoint public IP verification, IPv6 leak detection, VPN tunnel monitoring, and WebRTC checks.
- **M4 â€” Firewall Protection**: Windows Filtering Platform (WFP) and Linux nftables adapters, simulation mode, and fail-closed kill switch.
- **M5 â€” Advanced Routing**: Multi-hop routing chains, route verification, and exit node monitoring.
- **M6 â€” Tracker & Obfuscation**: DNS tracker blocklist filtering, obfs4 transport validation, and bridge health checks.
- **M7 â€” Identity & Footprint**: Identity isolation (personal vs research), metadata inspection, and exposure review.
- **M8 â€” Honeypot & Deception Lab**: Isolated decoy honeypots (SSH, HTTP, API) with local event recording.
- **M9 â€” GUI & CLI Integration**: React/TypeScript desktop GUI, authenticated local Go API server, and startup switcher.
- **M10 â€” Final Security Audit**: Cross-platform testing (Windows, Linux, Kali), failure injection, and release builds.
