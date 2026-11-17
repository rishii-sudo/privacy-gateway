# CLI Reference Guide â€” Privacy Gateway

**Developer:** 48sh1xbh

---

## 1. Application Startup

Running `privacy-gateway` without flags opens the master interactive startup menu:

```text
PRIVACY GATEWAY

Welcome to Privacy Gateway.

Select your interface:

[1] GUI Mode
[2] CLI Mode
[3] System Diagnostics
[4] Exit

Developed by 48sh1xbh

>
```

### Options:
- **`[1] GUI Mode`**: Launches the desktop interface. (In M1, displays status noting that React/TypeScript desktop GUI is planned for Milestone 9).
- **`[2] CLI Mode`**: Drops into the interactive Privacy Gateway CLI shell.
- **`[3] System Diagnostics`**: Immediately executes read-only system and network diagnostics.
- **`[4] Exit`**: Safely terminates the application.

---

## 2. Command-Line Flags

```bash
# Display version and developer attribution
privacy-gateway --version

# Run system diagnostics directly from terminal
privacy-gateway --diagnostics

# Launch interactive CLI mode directly
privacy-gateway --cli

# Launch GUI mode directly
privacy-gateway --gui

# Display help and usage instructions
privacy-gateway --help
```

---

## 3. Subcommands

Privacy Gateway commands can be executed non-interactively in automation scripts or terminal sessions:

### `status`
Displays current health, active interface counts, logging configuration, and firewall policy mode.
```bash
privacy-gateway status
```

### `check`
Executes all implemented baseline privacy checks and displays the formatted terminal summary.
```bash
privacy-gateway check

# Output in JSON format
privacy-gateway check --json
```

### `report`
Executes verification checks, formats the full audit report (including remediations and mandatory disclaimer), and saves a persistent JSON report in `Reports/`.
```bash
privacy-gateway report

# Output JSON to stdout and save to Reports/
privacy-gateway report --json
```

### `diagnostics`
Performs read-only host and network enumeration (OS, arch, memory, CPU, interfaces, MAC addresses, DNS resolvers, and route candidates).
```bash
privacy-gateway diagnostics
```

---

## 4. Interactive CLI Shell Commands

When in interactive CLI mode (`privacy-gateway --cli` or choosing `[2]` from the startup menu):

```text
pg-cli> help
Available CLI commands:
  status        Display application and privacy engine status
  check         Run all baseline privacy and security verification checks
  report        Generate detailed audit report (add --json for JSON format)
  diagnostics   Perform read-only system and network diagnostics
  logs          View recent structured logs
  recycle       List archived log files in Recycle Bin
  help          Show this command reference
  exit          Return to main menu
```
