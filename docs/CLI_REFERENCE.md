# Privacy Gateway CLI Reference

**Developer:** 48sh1xbh

## 1. Application startup

Running `privacy-gateway` without flags opens the startup interface. The available paths include CLI mode, diagnostics, and exit. A GUI is not part of the current M2 release scope unless separately implemented in the checked-out build.

## 2. Command-line flags

```bash
privacy-gateway --version
privacy-gateway --diagnostics
privacy-gateway --cli
privacy-gateway --gui
privacy-gateway --help
```

## 3. Foundation subcommands

```bash
privacy-gateway status
privacy-gateway check
privacy-gateway check --json
privacy-gateway report
privacy-gateway report --json
privacy-gateway diagnostics
```

- `status` displays application and privacy-engine status.
- `check` runs implemented baseline privacy checks.
- `report` generates the audit report and may save it under the configured report directory.
- `diagnostics` performs host and network diagnostics.

## 4. Interactive CLI

When interactive CLI mode is active, use `help` to display the commands supported by the running build. Common commands include `status`, `check`, `report`, `diagnostics`, `logs`, `recycle`, `help`, and `exit`.

## 5. Tor monitoring (M2)

Tor integration is disabled by default in `configs/default.yaml`. Configure a local Tor ControlPort and SAFECOOKIE cookie path before enabling it. SAFECOOKIE is mandatory; the client does not silently downgrade authentication.

```bash
# Daemon presence, control reachability, authentication, and monitoring health
privacy-gateway tor status

# Bootstrap progress and phase
privacy-gateway tor bootstrap

# Active circuits and relay fingerprints
privacy-gateway tor circuits

# Stream selected asynchronous events for five seconds (default)
privacy-gateway tor events
privacy-gateway tor events 30s

# Detailed Tor integration diagnostics
privacy-gateway tor diagnostics
```

### Operational boundaries

- M2 is observational. It does not modify Tor configuration, firewall rules, routing tables, or system proxy settings.
- `SIGNAL NEWNYM` is intentionally disabled.
- A successful ControlPort connection does not mean all host traffic is routed through Tor. Applications must separately use a correctly configured SOCKS proxy or independently verified routing policy.
- TCP ControlPort connections do not provide kernel peer-credential verification. Use a supported local Unix-domain socket when that assurance is required.
- Commands return an error when their requested operation fails. Check daemon availability, ControlPort configuration, and cookie-file permissions before retrying.
