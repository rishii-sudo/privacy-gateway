# Milestone 1 Specification â€” Foundation (Revised)

**Project:** Privacy Gateway
**Developer:** 48sh1xbh
**Milestone:** M1 â€” Foundation

---

## 1. Objectives

Milestone 1 establishes the operational core of Privacy Gateway. It delivers:
- Modular, idiomatic Go codebase.
- Safe YAML configuration management with validation.
- Read-only system discovery and health monitoring.
- Read-only network interface enumeration and DNS resolver discovery.
- The four-state verification status engine (`PASS`, `FAIL`, `INCONCLUSIVE`, `NOT_IMPLEMENTED`).
- Baseline privacy audit checks with actionable remediation advice.
- Terminal and JSON audit reporting with the mandatory anonymity disclaimer.
- The terminal startup experience and CLI commands.
- Multi-category local logging with hardware/secret redaction and a Recycle Bin archive workflow.
- Strict read-only invariant with respect to system network and firewall settings.

---

## 2. Baseline Privacy Checks in M1 (Revised Verification Rules)

### Core Principle: Insufficient Evidence Must Yield `INCONCLUSIVE`
A fundamental privacy engineering principle is that absent definitive proof, an audit check must never issue a speculative `PASS` or premature `FAIL`. In M1, with strictly read-only local enumeration, the verification rules adhere to:

### Check 1: Interface Exposure (`SYS_IFACE_EXPOSURE`)
- **Objective:** Evaluate active network interfaces against potential exposure risks using kernel metadata, MAC OUIs, and driver characteristics.
- **Classification Categories:**
  - `Physical Ethernet`: Direct hardware Ethernet adapters (e.g. Realtek, Intel GbE).
  - `Physical Wi-Fi`: Native 802.11 wireless adapters (e.g. MediaTek, Intel Wireless).
  - `Virtual (VM)`: Virtual machine hypervisor adapters (e.g. VMware VMnet1, VMnet8, VirtualBox, Hyper-V, QEMU virbr, WSL veth).
  - `Virtual (VPN/Tunnel)`: Encrypted tunnel and virtual adapters (e.g. WireGuard, OpenVPN, TAP-ProtonVPN, Tailscale, Wintun).
  - `Loopback`: Software loopback.
  - `Down`: Inactive / unlinked adapters.
  - `Unknown`: Adapters with insufficient metadata to establish classification.
- **Verification Rules:**
  - `PASS`: No physical interfaces active (e.g. host is completely air-gapped, running loopback-only, or only isolated VM adapters are active).
  - `FAIL`: Active physical interfaces (Ethernet, Wi-Fi) running with **no** detected VPN or tunnel interfaces on the host.
  - `INCONCLUSIVE`: A virtual/VPN interface (e.g. `wg0`, `tun0`, `tap`) is detected while physical interfaces are active. **Reason:** A detected VPN interface does not prove traffic is actually routed through it (routing table entries, bypasses, or split tunneling require active route verification in M3). Also returns `INCONCLUSIVE` if any active adapter cannot be reliably classified (`TypeUnknown`) instead of guessing.
- **Remediation:** Configure a verified system-wide VPN tunnel or enforce an isolated system routing policy to route all operating system traffic securely. (Note: Tor operates as an application proxy by default and does not automatically shield system-wide network traffic without transparent proxying or routing configuration).

### Check 2: IPv6 Dual-Stack Leak Risk (`SYS_IPV6_LEAK_RISK`)
- **Objective:** Identify whether global unicast IPv6 addresses are bound to active physical interfaces.
- **Revised Rules:**
  - `PASS`: No global unicast IPv6 addresses discovered on active non-loopback interfaces.
  - `INCONCLUSIVE`: Global unicast IPv6 addresses are present on active interfaces. **Reason:** A global IPv6 address does not automatically establish an active leak. Traffic may be firewall-filtered or unrouted; definitive leak verification requires M3 egress tests.
- **Remediation:** If your VPN or proxy does not route IPv6, disable IPv6 on the host or enforce firewall rules (M4) to prevent dual-stack leakage.

### Check 3: Hostname Identifier Leak (`SYS_HOSTNAME_DISCOVERY`)
- **Objective:** Audit system hostname to prevent local network (DHCP, mDNS, NetBIOS) user identification.
- **Revised Rules:**
  - `PASS`: Hostname is generic and does not contain user login names or potentially identifying vendor/hardware/model keywords (e.g. `alienware`, `thinkpad`, `macbook`, `surface`, `dell`).
  - `INCONCLUSIVE`: Hostname contains user account names or vendor/device/hardware identifiers. **Reason:** A local hostname does not prove network exposure unless active broadcast protocols (mDNS/LLMNR/DHCP Option 12) are verified transmitting it across the wire.
- **Remediation:** Configure a generic randomized hostname (e.g. using random alphanumeric characters), or verify that local network name broadcasting is disabled.

### Check 4: DNS Resolver Privacy (`NET_DNS_RESOLVER_PRIVACY`)
- **Objective:** Inspect configured system DNS servers.
- **Revised Rules:**
  - `INCONCLUSIVE` (Private Resolver): Configured resolvers are local/private IP addresses (`192.168.x.x`, `10.x.x.x`, `127.0.0.1`). **Reason:** A private DNS resolver does not prove plaintext ISP DNS; it may be an encrypted local stub (DoH/DoT) or router forwarder.
  - `INCONCLUSIVE` (Public Resolver): Configured resolvers are public IPs (`1.1.1.1`, `9.9.9.9`). **Reason:** A public DNS resolver does not prove encrypted DNS; standard OS lookups typically use unencrypted UDP/53.
  - `INCONCLUSIVE` (No Resolver): No resolvers configured or discoverable.
- **Remediation:** Configure an encrypted DNS client (DoH/DoT) to prevent plaintext DNS sniffing on local and transit networks.

---

## 3. Mandatory Anonymity Disclaimer

All generated reports, CLI diagnostics, and visual presentations must include the mandatory disclaimer:

> **DISCLAIMER:** Privacy Gateway provides verification, monitoring, and defensive controls. No software tool can guarantee absolute anonymity or immunity from network surveillance or advanced traffic analysis. Use responsibly and in accordance with applicable laws and policies.

---

## 4. Logging & Recycle Bin Model

- **Active Logs:** Stored in `Logs/privacy-gateway.log`.
- **Redaction-Before-Buffering:** Sensitive data (MAC addresses, passwords, bearer tokens, private keys) are scrubbed before appending to in-memory buffers or writing to disk.
- **Automated Size Rotation:** Logs automatically rotate when exceeding `max_file_size_bytes` (default 10MB), archiving to the Recycle Bin.
- **Recycle Bin:** Archived logs are safely stored in `Recycle Bin/` with UTC timestamp suffixes (`privacy-gateway.log-YYYYMMDD-HHMMSS.archived`). Users can inspect, restore (with path-traversal safeguards), and purge archives by retention period.
- **Local-Only Guarantee:** Telemetry is disabled by default, and no logs or telemetry are transmitted to third-party endpoints.
- **Strict Read-Only Guarantee:** M1 strictly avoids modifying host network or firewall settings.
