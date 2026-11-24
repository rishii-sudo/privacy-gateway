package privacy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
	"github.com/rishii-sudo/privacy-gateway/internal/network"
	"github.com/rishii-sudo/privacy-gateway/internal/tor"
)

// Checker executes baseline privacy and security audits against the host system.
type Checker struct {
	cfg        *config.Config
	enumerator *network.NetworkEnumerator
	torClient  *tor.Client
}

// NewChecker initializes a new Checker with the given configuration.
func NewChecker(cfg *config.Config) *Checker {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	enum := network.NewEnumerator(cfg.Network.VirtualInterfacePrefixes, cfg.Network.ProbeTimeout)
	return &Checker{
		cfg:        cfg,
		enumerator: enum,
	}
}

// SetTorClient injects a Tor client instance into the Checker.
func (c *Checker) SetTorClient(client *tor.Client) {
	c.torClient = client
}

// RunAllBaselineChecks executes all implemented M1/M2 checks and stubs future milestone checks
// with typed NOT_IMPLEMENTED status.
func (c *Checker) RunAllBaselineChecks() ([]CheckResult, error) {
	var results []CheckResult

	// 1. Interface Exposure Check
	results = append(results, c.CheckInterfaceExposure())

	// 2. IPv6 Leak Risk Check
	results = append(results, c.CheckIPv6Exposure())

	// 3. Local Hostname Fingerprint Check
	results = append(results, c.CheckHostnameExposure())

	// 4. DNS Resolver Privacy Check
	results = append(results, c.CheckDNSResolverPrivacy())

	// 5. Tor Control Authentication Check (M2)
	results = append(results, c.CheckTorAuth())

	// 6. Tor Daemon Bootstrap Check (M2)
	results = append(results, c.CheckTorBootstrap())

	// 7. Tor Circuit Status and Health Check (M2)
	results = append(results, c.CheckTorCircuitStatus())

	// Future Milestone Verification Stubs (All NOT_IMPLEMENTED in M2)

	results = append(results, c.stubCheck(
		"VPN_TUNNEL_CONNECTIVITY",
		"VPN Tunnel Connectivity and Route Check",
		CategoryVPN,
		"VPN tunnel monitoring and routing profiles are scheduled for Milestone 3 (M3).",
	))

	results = append(results, c.stubCheck(
		"NET_PUBLIC_IP_LEAK",
		"Multi-Endpoint Public IP and WebRTC Leak Check",
		CategoryNetwork,
		"Independent multi-endpoint public IP verification is scheduled for Milestone 3 (M3).",
	))

	results = append(results, c.stubCheck(
		"FIREWALL_KILLSWITCH_STATE",
		"Fail-Closed Firewall Kill Switch",
		CategoryFirewall,
		"Firewall kill switch (WFP/nftables) is scheduled for Milestone 4 (M4).",
	))

	results = append(results, c.stubCheck(
		"ROUTING_MULTIHOP_VERIFY",
		"Multi-Hop Routing Chain Verification",
		CategoryRouting,
		"Multi-hop routing verification is scheduled for Milestone 5 (M5).",
	))

	results = append(results, c.stubCheck(
		"TRACKER_FILTER_STATUS",
		"System-Wide DNS Tracker Filtering",
		CategoryTracker,
		"DNS tracker blocklist filtering is scheduled for Milestone 6 (M6).",
	))

	results = append(results, c.stubCheck(
		"OBFUSCATION_HEALTH",
		"Transport Obfuscation Verification",
		CategoryObfuscation,
		"obfs4 and bridge obfuscation health is scheduled for Milestone 6 (M6).",
	))

	results = append(results, c.stubCheck(
		"ISOLATION_BOUNDARY",
		"Identity and Lab Environment Isolation",
		CategoryIsolation,
		"Environment isolation boundary verification is scheduled for Milestone 7 (M7).",
	))

	results = append(results, c.stubCheck(
		"DECEPTION_HONEYPOT_STATE",
		"Isolated Deception Honeypot State",
		CategoryDeception,
		"Isolated research honeypots are scheduled for Milestone 8 (M8).",
	))

	return results, nil
}

// CheckInterfaceExposure analyzes active physical interfaces vs tunnel/VPN interfaces.
// Principle: A detected VPN interface does not prove traffic is routed through it.
// Therefore, the presence of a VPN interface along with physical interfaces is INCONCLUSIVE
// until routing is verified in Milestone 3.
func (c *Checker) CheckInterfaceExposure() CheckResult {
	id := "SYS_IFACE_EXPOSURE"
	name := "Network Interface Exposure Check"
	cat := CategorySystem

	ifaces, err := c.enumerator.EnumerateInterfaces()
	if err != nil {
		return NewCheckResult(id, name, cat, StatusInconclusive, "Failed to enumerate network interfaces: "+err.Error()).
			WithRemediation("Verify system permissions to query local network interfaces.")
	}

	var activePhysical []string
	var activeVPN []string
	var activeVM []string
	var activeUnknown []string

	for _, iface := range ifaces {
		if !iface.IsUp || iface.Type.IsLoopback() || iface.Type.IsDown() {
			continue
		}
		if iface.Type.IsUnknown() {
			activeUnknown = append(activeUnknown, iface.Name)
		} else if iface.Type.IsVPN() {
			activeVPN = append(activeVPN, iface.Name)
		} else if iface.Type.IsVM() {
			activeVM = append(activeVM, iface.Name)
		} else if iface.Type.IsPhysical() {
			activePhysical = append(activePhysical, iface.Name)
		}
	}

	details := map[string]interface{}{
		"active_physical_interfaces": activePhysical,
		"active_vpn_interfaces":      activeVPN,
		"active_vm_interfaces":       activeVM,
		"active_unknown_interfaces":  activeUnknown,
	}

	// Requirement 5: If reliable interface classification is unavailable, return INCONCLUSIVE instead of guessing.
	if len(activeUnknown) > 0 {
		return NewCheckResult(id, name, cat, StatusInconclusive,
			fmt.Sprintf("Interface classification inconclusive: adapter(s) (%s) could not be reliably classified as physical or virtual. Reliable interface metadata is required to evaluate exposure.",
				strings.Join(activeUnknown, ", "))).
			WithDetails(details).
			WithRemediation("Verify system network adapter drivers or inspect interface properties.")
	}

	// Case 1: No active physical interfaces (e.g., host has only loopback, is air-gapped, or only virtual VM adapters)
	if len(activePhysical) == 0 {
		msg := "No active physical network interfaces detected."
		if len(activeVM) > 0 {
			msg = fmt.Sprintf("No active physical network interfaces detected (isolated virtual machine adapters active: %s).",
				strings.Join(activeVM, ", "))
		}
		return NewCheckResult(id, name, cat, StatusPass, msg).
			WithDetails(details)
	}

	// Case 2: Virtual/VPN interface detected, but physical interfaces are also active
	// Requirement: A detected VPN interface does not prove traffic is routed through it.
	if len(activeVPN) > 0 {
		return NewCheckResult(id, name, cat, StatusInconclusive,
			fmt.Sprintf("VPN/tunnel interface detected (%s), but routing verification is required (M3) to confirm traffic flows through the tunnel. Physical interface(s) (%s) remain active.",
				strings.Join(activeVPN, ", "), strings.Join(activePhysical, ", "))).
			WithDetails(details).
			WithRemediation("Verify system-wide routing table entries or wait for Milestone 3 route leak verification to confirm all egress traffic flows through the tunnel, rather than bypassing it via physical interfaces.")
	}

	// Case 3: Active physical interfaces running with zero VPN/tunnel interfaces
	// Requirement 6: Correct remediation text:
	// - Do not claim that launching Tor automatically shields all system traffic.
	// - Explain that a verified system-wide VPN route or properly enforced routing policy is required for system-wide traffic protection.
	return NewCheckResult(id, name, cat, StatusFail,
		fmt.Sprintf("Exposed: Active physical interface(s) (%s) operating with no virtual/VPN tunnel interface detected.",
			strings.Join(activePhysical, ", "))).
		WithDetails(details).
		WithRemediation("Configure a verified system-wide VPN tunnel or enforce an isolated system routing policy to route all operating system traffic securely. Note: Tor operates as an application proxy by default and does not automatically shield system-wide network traffic without transparent proxying or routing configuration.")
}

// CheckIPv6Exposure checks if routable global unicast IPv6 is assigned to active interfaces.
// Principle: A global IPv6 address does not automatically establish an active leak.
// Without active external route and egress testing (M3), presence of global IPv6 is INCONCLUSIVE.
func (c *Checker) CheckIPv6Exposure() CheckResult {
	id := "SYS_IPV6_LEAK_RISK"
	name := "IPv6 Dual-Stack Leak Risk"
	cat := CategoryNetwork

	ifaces, err := c.enumerator.EnumerateInterfaces()
	if err != nil {
		return NewCheckResult(id, name, cat, StatusInconclusive, "Unable to inspect IPv6 interface bindings: "+err.Error()).
			WithRemediation("Verify network permission settings.")
	}

	var exposedIPv6Addrs []string
	var affectedInterfaces []string

	for _, iface := range ifaces {
		if !iface.IsUp || iface.Type.IsLoopback() {
			continue
		}
		for _, addr := range iface.Addresses {
			if addr.Family == "IPv6" && addr.IsGlobalUnicast && !addr.IsLoop {
				exposedIPv6Addrs = append(exposedIPv6Addrs, addr.CIDR)
				affectedInterfaces = append(affectedInterfaces, iface.Name)
			}
		}
	}

	details := map[string]interface{}{
		"global_unicast_ipv6_count": len(exposedIPv6Addrs),
		"affected_interfaces":       affectedInterfaces,
	}

	// Case 1: No global unicast IPv6 addresses on external interfaces
	if len(exposedIPv6Addrs) == 0 {
		return NewCheckResult(id, name, cat, StatusPass, "No public or global unicast IPv6 addresses discovered on active interfaces.").
			WithDetails(details)
	}

	// Case 2: Global unicast IPv6 addresses discovered
	// Important Correction: A global IPv6 address does not automatically establish a leak.
	// Dual-stack is enabled, but traffic might be firewall-filtered or unrouted.
	return NewCheckResult(id, name, cat, StatusInconclusive,
		fmt.Sprintf("Dual-stack IPv6 address(es) discovered on active interface(s) (%s). Global IPv6 indicates a dual-stack configuration, but active traffic leakage cannot be proven without M3 egress verification.",
			strings.Join(affectedInterfaces, ", "))).
		WithDetails(details).
		WithRemediation("If your VPN or proxy does not route IPv6, disable IPv6 on the host or enforce firewall rules (M4) to prevent potential dual-stack leaks.")
}

// CheckHostnameExposure checks if system hostname reveals hardware or vendor identifiers.
// Principle: A local hostname does not prove network exposure.
// Conservatively treats identifying vendor, hardware, or environment names as INCONCLUSIVE.
// Per privacy engineering requirements, no OS username information is queried or recorded.
func (c *Checker) CheckHostnameExposure() CheckResult {
	id := "SYS_HOSTNAME_DISCOVERY"
	name := "Local Hostname Identifier Check"
	cat := CategorySystem

	hostname, err := os.Hostname()
	if err != nil {
		return NewCheckResult(id, name, cat, StatusInconclusive, "Could not determine local system hostname").
			WithRemediation("Ensure host OS environment variables and system files are accessible.")
	}

	lowerHost := strings.ToLower(hostname)
	details := map[string]interface{}{
		"hostname": hostname,
	}

	suspicious := false
	var reasons []string

	// Identifying vendor brands and hardware manufacturers
	vendorKeywords := []string{
		"alienware", "thinkpad", "macbook", "surface", "dell", "lenovo",
		"asus", "acer", "hp", "hewlett", "msi", "razer", "sony", "vaio",
		"samsung", "toshiba", "fujitsu", "huawei", "apple",
	}
	for _, kw := range vendorKeywords {
		if strings.Contains(lowerHost, kw) {
			reasons = append(reasons, fmt.Sprintf("contains vendor/hardware brand %q", kw))
			suspicious = true
			break
		}
	}

	// Identifying form-factors and default OS prefixes
	deviceKeywords := []string{
		"desktop-", "laptop-", "pc-", "win-", "kali-", "ubuntu-",
		"debian-", "fedora-", "arch-", "workstation", "notebook",
		"server", "tower", "rig",
	}
	for _, kw := range deviceKeywords {
		if strings.Contains(lowerHost, kw) {
			reasons = append(reasons, fmt.Sprintf("contains hardware/OS device pattern %q", kw))
			suspicious = true
			break
		}
	}

	// Environment / location markers
	envKeywords := []string{"home", "office", "work", "corp", "lab", "lan"}
	for _, kw := range envKeywords {
		if strings.Contains(lowerHost, kw) {
			reasons = append(reasons, fmt.Sprintf("contains environment marker %q", kw))
			suspicious = true
			break
		}
	}

	// Case 1: Hostname contains vendor, hardware, or environment identifiers
	// Conservatively classified as INCONCLUSIVE
	if suspicious {
		return NewCheckResult(id, name, cat, StatusInconclusive,
			fmt.Sprintf("Hostname %q contains potentially identifying vendor, hardware, or environment keywords (%s). While this presents an identification risk on local networks (via DHCP/mDNS/LLMNR), local hostname alone does not prove network broadcast exposure without active protocol inspection.",
				hostname, strings.Join(reasons, ", "))).
			WithDetails(details).
			WithRemediation("Configure a generic, randomized hostname (e.g., using random alphanumeric characters) to prevent hardware vendor or device fingerprinting on local networks.")
	}

	// Case 2: Hostname does not match vendor or common device patterns
	return NewCheckResult(id, name, cat, StatusPass,
		fmt.Sprintf("Hostname %q is generic and does not contain vendor, device, or environment identifiers.", hostname)).
		WithDetails(details)
}

// CheckDNSResolverPrivacy inspects configured DNS servers.
// Principles:
// 1. A private DNS resolver does not prove plaintext ISP DNS (could be local DoH/DoT stub).
// 2. A public DNS resolver does not prove encrypted DNS (could use plaintext UDP/53).
// Therefore, static resolver discovery in M1 is INCONCLUSIVE in both cases.
func (c *Checker) CheckDNSResolverPrivacy() CheckResult {
	id := "NET_DNS_RESOLVER_PRIVACY"
	name := "DNS Resolver Privacy Configuration"
	cat := CategoryNetwork

	dnsCfg := network.DiscoverDNSResolvers(c.cfg.Network.DnsServers)

	details := map[string]interface{}{
		"dns_servers": dnsCfg.Servers,
		"source":      dnsCfg.Source,
	}

	if len(dnsCfg.Servers) == 0 {
		return NewCheckResult(id, name, cat, StatusInconclusive, "No DNS servers configured or discovered.").
			WithDetails(details).
			WithRemediation("Configure at least one reliable privacy-focused DNS resolver.")
	}

	var localResolvers []string
	var publicResolvers []string

	for _, s := range dnsCfg.Servers {
		ip := net.ParseIP(s)
		if ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
			localResolvers = append(localResolvers, s)
		} else {
			publicResolvers = append(publicResolvers, s)
		}
	}

	// Case 1: Private or loopback resolvers present
	// Important Correction: A private DNS resolver does not prove plaintext ISP DNS.
	// It could be a local caching resolver with DoH/DoT upstream (e.g. Pi-hole, Unbound, stubby).
	if len(localResolvers) > 0 {
		return NewCheckResult(id, name, cat, StatusInconclusive,
			fmt.Sprintf("Configured DNS resolver(s) are local/private IP addresses (%s). A private resolver does not prove plaintext ISP DNS; it may be an encrypted local stub (DoH/DoT) or router forwarder. Active query inspection (M3) is required to determine transport security.",
				strings.Join(localResolvers, ", "))).
			WithDetails(details).
			WithRemediation("Verify whether the local DNS resolver encrypts upstream queries via DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT).")
	}

	// Case 2: Public resolvers configured
	// Important Correction: A public DNS resolver does not prove encrypted DNS.
	// Standard OS queries to 1.1.1.1 or 9.9.9.9 often use unencrypted UDP/53 unless a DoH/DoT proxy is active.
	return NewCheckResult(id, name, cat, StatusInconclusive,
		fmt.Sprintf("Public DNS resolver(s) configured (%s). A public resolver IP does not prove encrypted DNS; standard system lookups may use unencrypted UDP/53 without an encrypted DNS proxy.",
			strings.Join(publicResolvers, ", "))).
		WithDetails(details).
		WithRemediation("Configure an encrypted DNS client (DoH/DoT) to prevent plaintext DNS sniffing on local and transit networks.")
}

// stubCheck creates a typed NOT_IMPLEMENTED result for future milestone features.
func (c *Checker) stubCheck(id, name string, cat Category, summary string) CheckResult {
	res := NewCheckResult(id, name, cat, StatusNotImplemented, summary)
	res.Timestamp = time.Now().UTC()
	return res
}

func (c *Checker) ensureTorClient(ctx context.Context) (*tor.Client, error) {
	if c.torClient != nil {
		return c.torClient, nil
	}
	if !c.cfg.Tor.Enabled {
		return nil, errors.New("Tor integration is disabled in configuration (tor.enabled=false)")
	}

	client := tor.NewClient(c.cfg, nil)
	c.torClient = client
	return client, nil
}

// CheckTorAuth verifies connectivity and SAFECOOKIE authentication with the local Tor daemon.
func (c *Checker) CheckTorAuth() CheckResult {
	res := NewCheckResult(
		"TOR_CONTROL_AUTH",
		"Tor Control Port Authentication",
		CategoryTor,
		StatusInconclusive,
		"Tor control authentication verification",
	)

	if !c.cfg.Tor.Enabled && c.torClient == nil {
		res.Status = StatusInconclusive
		res.Summary = "Tor control verification skipped: Tor is disabled in configuration (tor.enabled=false)"
		res.Details = map[string]interface{}{
			"enabled":          false,
			"control_endpoint": c.cfg.Tor.ControlEndpoint,
		}
		res.Remediation = "Enable Tor in configuration (tor.enabled: true) or provide --tor flag to verify Tor daemon."
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Tor.ConnectionTimeout)
	defer cancel()

	client, err := c.ensureTorClient(ctx)
	if err != nil {
		res.Status = StatusInconclusive
		res.Summary = fmt.Sprintf("Tor daemon unavailable: %v", err)
		res.Details = map[string]interface{}{
			"endpoint": c.cfg.Tor.ControlEndpoint,
			"error":    err.Error(),
		}
		res.Remediation = "Ensure Tor daemon is installed and running with ControlPort 9051."
		return res
	}

	// Connect if not already connected
	if client.State() == tor.StateDisconnected || client.State() == tor.StateClosed {
		if err := client.Connect(ctx); err != nil {
			res.Status = StatusInconclusive
			res.Summary = fmt.Sprintf("Tor control endpoint %s unreachable: %v", c.cfg.Tor.ControlEndpoint, err)
			res.Details = map[string]interface{}{
				"endpoint": c.cfg.Tor.ControlEndpoint,
				"error":    err.Error(),
			}
			res.Remediation = "Ensure Tor daemon is running and listening on local ControlPort 9051."
			return res
		}
	}

	// Authenticate if not already authenticated
	var authResult *tor.AuthResult
	if client.State() != tor.StateAuthenticated {
		authResult, err = client.Authenticate(ctx)
		if err != nil {
			if errors.Is(err, tor.ErrInvalidHMAC) || errors.Is(err, tor.ErrAuthFailed) {
				res.Status = StatusFail
				res.Summary = fmt.Sprintf("Tor ControlPort authentication failed closed: %v", err)
				res.Details = map[string]interface{}{
					"endpoint":      c.cfg.Tor.ControlEndpoint,
					"authenticated": false,
					"error":         err.Error(),
				}
				res.Remediation = "Verify Tor control cookie permissions and ensure SAFECOOKIE authentication is configured."
				return res
			}

			res.Status = StatusInconclusive
			res.Summary = fmt.Sprintf("Tor ControlPort negotiation failed: %v", err)
			res.Details = map[string]interface{}{
				"endpoint": c.cfg.Tor.ControlEndpoint,
				"error":    err.Error(),
			}
			res.Remediation = "Verify Tor control endpoint configuration and cookie permissions."
			return res
		}
	} else {
		authResult = client.LastAuthResult()
	}

	// Authentication PASS must depend strictly on confirmed, successful SAFECOOKIE authentication
	if authResult == nil || !authResult.Success || !strings.EqualFold(authResult.Method, "SAFECOOKIE") {
		res.Status = StatusFail
		res.Summary = "Tor ControlPort authentication verification failed: valid SAFECOOKIE authentication not confirmed"
		errStr := "SAFECOOKIE authentication not confirmed"
		if authResult != nil && authResult.Error != "" {
			errStr = authResult.Error
		}
		res.Details = map[string]interface{}{
			"endpoint":      c.cfg.Tor.ControlEndpoint,
			"authenticated": false,
			"error":         errStr,
		}
		res.Remediation = "Verify Tor control cookie permissions and ensure SAFECOOKIE authentication is configured."
		return res
	}

	// Handle GetVersion separately; do not silently report missing version information as successful retrieval
	ver, verErr := client.GetVersion(ctx)
	if verErr != nil {
		res.Status = StatusPass
		res.Summary = "Tor ControlPort authenticated successfully via SAFECOOKIE (version query failed)"
		res.Details = map[string]interface{}{
			"endpoint":      c.cfg.Tor.ControlEndpoint,
			"authenticated": true,
			"method":        "SAFECOOKIE",
			"version":       nil,
			"version_error": verErr.Error(),
			"caution":       "Tor control connection authenticated. Note: Control connection does NOT imply that system traffic is routed through Tor.",
		}
		return res
	}

	res.Status = StatusPass
	res.Summary = fmt.Sprintf("Tor ControlPort authenticated successfully via SAFECOOKIE (version: %s)", ver)
	res.Details = map[string]interface{}{
		"endpoint":      c.cfg.Tor.ControlEndpoint,
		"authenticated": true,
		"method":        "SAFECOOKIE",
		"version":       ver,
		"caution":       "Tor control connection authenticated. Note: Control connection does NOT imply that system traffic is routed through Tor.",
	}
	return res
}

// CheckTorBootstrap verifies whether the Tor daemon has completed bootstrap initialization.
func (c *Checker) CheckTorBootstrap() CheckResult {
	res := NewCheckResult(
		"TOR_DAEMON_BOOTSTRAP",
		"Tor Daemon Bootstrap Verification",
		CategoryTor,
		StatusInconclusive,
		"Tor daemon bootstrap status verification",
	)

	if !c.cfg.Tor.Enabled && c.torClient == nil {
		res.Status = StatusInconclusive
		res.Summary = "Tor daemon bootstrap check skipped: Tor is disabled in configuration"
		res.Remediation = "Enable Tor in configuration (tor.enabled: true) to verify bootstrap status."
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Tor.ConnectionTimeout)
	defer cancel()

	client, err := c.ensureTorClient(ctx)
	if err != nil || client.State() != tor.StateAuthenticated {
		res.Status = StatusInconclusive
		res.Summary = "Tor daemon bootstrap status could not be verified (controller not authenticated)"
		res.Remediation = "Ensure Tor daemon is running and control authentication succeeds."
		return res
	}

	boot, err := client.GetBootstrapStatus(ctx)
	if err != nil {
		res.Status = StatusInconclusive
		res.Summary = fmt.Sprintf("Failed to query Tor bootstrap status: %v", err)
		res.Details = map[string]interface{}{
			"error": err.Error(),
		}
		res.Remediation = "Inspect Tor daemon logs for bootstrap failures or directory connectivity issues."
		return res
	}

	res.Details = map[string]interface{}{
		"progress": boot.Progress,
		"tag":      boot.Tag,
		"summary":  boot.Summary,
		"ready":    boot.Ready,
	}

	if boot.Ready && boot.Progress == 100 {
		res.Status = StatusPass
		res.Summary = fmt.Sprintf("Tor daemon bootstrap complete: 100%% (%s)", boot.Tag)
		res.Details["caution"] = "Tor network bootstrap is complete. Note: Local applications still require explicit SOCKS5 proxy configuration to use Tor."
		return res
	}

	res.Status = StatusInconclusive
	res.Summary = fmt.Sprintf("Tor daemon bootstrap in progress: %d%% (%s: %s)", boot.Progress, boot.Tag, boot.Summary)
	if boot.Warning != "" {
		res.Details["warning"] = boot.Warning
	}
	res.Remediation = "Wait for Tor bootstrap to complete (100%) or check network connectivity and system clock synchronization."
	return res
}

// CheckTorCircuitStatus verifies whether active, multi-hop circuits have been established by the Tor daemon.
func (c *Checker) CheckTorCircuitStatus() CheckResult {
	res := NewCheckResult(
		"TOR_CIRCUIT_STATUS",
		"Tor Circuit Status and Health",
		CategoryTor,
		StatusInconclusive,
		"Tor circuit and relay health verification",
	)

	if !c.cfg.Tor.Enabled && c.torClient == nil {
		res.Status = StatusInconclusive
		res.Summary = "Tor circuit check skipped: Tor is disabled in configuration"
		res.Remediation = "Enable Tor in configuration (tor.enabled: true) to verify circuit status."
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Tor.ConnectionTimeout)
	defer cancel()

	client, err := c.ensureTorClient(ctx)
	if err != nil || client.State() != tor.StateAuthenticated {
		res.Status = StatusInconclusive
		res.Summary = "Tor circuit status could not be verified (controller not authenticated)"
		res.Remediation = "Ensure Tor daemon is running and control authentication succeeds."
		return res
	}

	established, err := client.GetCircuitEstablished(ctx)
	if err != nil {
		res.Status = StatusInconclusive
		res.Summary = fmt.Sprintf("Failed to query Tor circuit established status: %v", err)
		res.Details = map[string]interface{}{
			"error": err.Error(),
		}
		return res
	}

	circuits, err := client.GetActiveCircuits(ctx)
	if err != nil {
		res.Status = StatusInconclusive
		res.Summary = fmt.Sprintf("Failed to query Tor active circuits: %v", err)
		res.Details = map[string]interface{}{
			"error": err.Error(),
		}
		return res
	}

	builtCount := 0
	for _, circ := range circuits {
		if circ.Status == "BUILT" {
			builtCount++
		}
	}

	res.Details = map[string]interface{}{
		"circuit_established": established,
		"total_circuits":      len(circuits),
		"built_circuits":      builtCount,
		"monitoring_health":   string(client.MonitoringStatus().Health),
	}

	// Gap 1: Event queue overflow produces an explicit degraded monitoring state / INCONCLUSIVE result
	monStatus := client.MonitoringStatus()
	if monStatus.Health == tor.MonitoringHealthDegraded {
		res.Status = StatusInconclusive
		res.Summary = fmt.Sprintf("Tor circuit monitoring degraded: event queue overflow (%d events dropped)", monStatus.DroppedEvents)
		res.Details["dropped_events"] = monStatus.DroppedEvents
		res.Details["total_events"] = monStatus.TotalEvents
		res.Details["degraded_reason"] = monStatus.DegradedReason
		res.Remediation = "Increase tor.event_queue_limit in configuration or inspect consumer processing throughput to resolve event queue saturation."
		return res
	}

	if established && builtCount > 0 {
		res.Status = StatusPass
		res.Summary = fmt.Sprintf("Tor has %d established BUILT circuit(s) across the Tor network", builtCount)
		res.Details["caution"] = "Established Tor circuits are available for SOCKS streams. Host traffic is not automatically protected unless applications or system routing are explicitly configured."
		return res
	}

	res.Status = StatusInconclusive
	res.Summary = fmt.Sprintf("Tor circuits not ready: %d built circuit(s), circuit_established=%t", builtCount, established)
	res.Remediation = "Allow Tor daemon time to establish guard, middle, and exit relays."
	return res
}
