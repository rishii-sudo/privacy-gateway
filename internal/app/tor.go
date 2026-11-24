package app

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/tor"
)

// SetTorClient injects a Tor client into the application for testing or custom transports.
func (a *Application) SetTorClient(client *tor.Client) {
	a.torClient = client
	if a.Checker != nil {
		a.Checker.SetTorClient(client)
	}
}

// getTorClient returns the existing Tor client or creates and connects a new one.
func (a *Application) getTorClient(ctx context.Context) (*tor.Client, error) {
	if a.torClient == nil {
		a.torClient = tor.NewClient(a.Config, a.Logger)
	}

	client := a.torClient
	if client.State() == tor.StateAuthenticated {
		return client, nil
	}

	if client.State() == tor.StateDisconnected || client.State() == tor.StateClosed {
		if err := client.Connect(ctx); err != nil {
			return nil, fmt.Errorf("failed to connect to Tor ControlPort (%s): %w", a.Config.Tor.ControlEndpoint, err)
		}
	}

	if _, err := client.Authenticate(ctx); err != nil {
		return client, fmt.Errorf("Tor ControlPort authentication failed: %w", err)
	}

	if a.Checker != nil {
		a.Checker.SetTorClient(client)
	}

	return client, nil
}

// RunTorCommand routes Tor subcommands: status, bootstrap, circuits, events, diagnostics.
func (a *Application) RunTorCommand(out io.Writer, args []string) error {
	subcmd := "status"
	if len(args) > 0 {
		subcmd = strings.ToLower(args[0])
	}

	switch subcmd {
	case "status":
		return a.RunTorStatus(out)
	case "bootstrap":
		return a.RunTorBootstrap(out)
	case "circuits":
		return a.RunTorCircuits(out)
	case "events":
		duration := 5 * time.Second
		if len(args) > 1 {
			if d, err := time.ParseDuration(args[1]); err == nil && d > 0 {
				duration = d
			}
		}
		return a.RunTorEvents(out, duration)
	case "diagnostics":
		return a.RunTorDiagnostics(out)
	case "help", "-h", "--help":
		a.showTorHelp(out)
		return nil
	default:
		fmt.Fprintf(out, "Unknown Tor subcommand %q.\n\n", subcmd)
		a.showTorHelp(out)
		return nil
	}
}

func (a *Application) showTorHelp(out io.Writer) {
	fmt.Fprintln(out, "Usage: privacy-gateway tor [subcommand]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Available subcommands:")
	fmt.Fprintln(out, "  status        Display Tor daemon presence, control reachability, and health")
	fmt.Fprintln(out, "  bootstrap     Monitor Tor network bootstrap progress and phase")
	fmt.Fprintln(out, "  circuits      List active multi-hop circuits and relay fingerprints")
	fmt.Fprintln(out, "  events        Stream real-time asynchronous Tor daemon events")
	fmt.Fprintln(out, "  diagnostics   Perform deep diagnostic verification of Tor integration")
	fmt.Fprintln(out, "  help          Show this help message")
}

// RunTorStatus inspects and displays Tor daemon status, endpoint discovery, and control state.
func (a *Application) RunTorStatus(out io.Writer) error {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out, "  TOR DAEMON & CONTROL STATUS")
	fmt.Fprintln(out, "  Milestone 2 (M2) Native Tor Integration | Developed by 48sh1xbh")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")

	// Endpoint discovery
	candidates := tor.DiscoverLocalEndpoints(500 * time.Millisecond)
	fmt.Fprintln(out, "  Discovered Local Endpoints:")
	for _, c := range candidates {
		statusStr := "UNREACHABLE"
		if c.Active {
			statusStr = "ACTIVE"
		}
		fmt.Fprintf(out, "    • %-22s [%-4s] : %s\n", c.Endpoint, strings.ToUpper(c.Network), statusStr)
	}

	fmt.Fprintf(out, "\n  Configured Control Endpoint : %s\n", a.Config.Tor.ControlEndpoint)

	ctx, cancel := context.WithTimeout(context.Background(), a.Config.Tor.ConnectionTimeout)
	defer cancel()

	client, err := a.getTorClient(ctx)
	if err != nil {
		fmt.Fprintf(out, "  Control Authentication     : FAILED (%v)\n", err)
		fmt.Fprintln(out, "\n  REMEDIATION: Ensure Tor daemon is running with ControlPort 9051 and CookieAuthentication 1.")
		fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
		fmt.Fprintln(out)
		return err
	}

	version, _ := client.GetVersion(ctx)
	fmt.Fprintf(out, "  Control Authentication     : SUCCESS (SAFECOOKIE)\n")
	fmt.Fprintf(out, "  Tor Daemon Version         : %s\n", version)

	boot, err := client.GetBootstrapStatus(ctx)
	if err == nil {
		fmt.Fprintf(out, "  Bootstrap Progress         : %d%% (%s: %s)\n", boot.Progress, boot.Tag, boot.Summary)
	}

	est, err := client.GetCircuitEstablished(ctx)
	if err == nil {
		estStr := "No"
		if est {
			estStr = "Yes"
		}
		fmt.Fprintf(out, "  Circuit Established        : %s\n", estStr)
	}

	monStatus := client.MonitoringStatus()
	if monStatus.Health == tor.MonitoringHealthDegraded {
		fmt.Fprintf(out, "  Monitoring Health          : DEGRADED (%d events dropped: queue saturation)\n", monStatus.DroppedEvents)
	} else {
		fmt.Fprintf(out, "  Monitoring Health          : NORMAL\n")
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "  CAUTION: Tor control connection active. Tor does NOT automatically shield")
	fmt.Fprintln(out, "  all system traffic. Verified SOCKS5 proxy (127.0.0.1:9050) or routing policy")
	fmt.Fprintln(out, "  is required to protect host network streams.")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out)
	return nil
}

// RunTorBootstrap queries and displays Tor network bootstrap progress.
func (a *Application) RunTorBootstrap(out io.Writer) error {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out, "  TOR DAEMON BOOTSTRAP MONITOR")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")

	ctx, cancel := context.WithTimeout(context.Background(), a.Config.Tor.ConnectionTimeout)
	defer cancel()

	client, err := a.getTorClient(ctx)
	if err != nil {
		fmt.Fprintf(out, "  Error: %v\n", err)
		fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
		return err
	}

	boot, err := client.GetBootstrapStatus(ctx)
	if err != nil {
		fmt.Fprintf(out, "  Failed to query bootstrap status: %v\n", err)
		fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
		return err
	}

	// Visual progress bar
	blocks := boot.Progress / 5
	bar := strings.Repeat("█", blocks) + strings.Repeat("░", 20-blocks)

	fmt.Fprintf(out, "  Progress          : [%s] %d%%\n", bar, boot.Progress)
	fmt.Fprintf(out, "  Phase Tag         : %s\n", boot.Tag)
	fmt.Fprintf(out, "  Phase Summary     : %s\n", boot.Summary)
	if boot.Warning != "" {
		fmt.Fprintf(out, "  Warning           : %s\n", boot.Warning)
	}
	readyStr := "No"
	if boot.Ready {
		readyStr = "Yes"
	}
	fmt.Fprintf(out, "  Ready For Traffic : %s\n", readyStr)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  NOTE: Local applications must configure SOCKS proxy (default 127.0.0.1:9050)")
	fmt.Fprintln(out, "  to route traffic through the Tor network.")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out)
	return nil
}

// RunTorCircuits queries and displays active multi-hop Tor circuits.
func (a *Application) RunTorCircuits(out io.Writer) error {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out, "  TOR CIRCUIT STATUS & RELAYS")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")

	ctx, cancel := context.WithTimeout(context.Background(), a.Config.Tor.ConnectionTimeout)
	defer cancel()

	client, err := a.getTorClient(ctx)
	if err != nil {
		fmt.Fprintf(out, "  Error: %v\n", err)
		fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
		return err
	}

	established, err := client.GetCircuitEstablished(ctx)
	if err != nil {
		fmt.Fprintf(out, "  Circuit Established Query: FAILED (%v)\n", err)
	} else {
		estStr := "No"
		if established {
			estStr = "Yes"
		}
		fmt.Fprintf(out, "  Circuit Established: %s\n", estStr)
	}

	circuits, err := client.GetActiveCircuits(ctx)
	if err != nil {
		fmt.Fprintf(out, "  Active Circuits Query: FAILED (%v)\n", err)
		fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
		return err
	}

	fmt.Fprintf(out, "  Active Circuits    : %d\n\n", len(circuits))
	if len(circuits) == 0 {
		fmt.Fprintln(out, "  (No active circuits currently established)")
	}

	for _, c := range circuits {
		fmt.Fprintf(out, "  [Circuit %s] Status: %-8s | Purpose: %s\n", c.ID, c.Status, c.Purpose)
		for idx, hop := range c.Path {
			hopRole := "Middle"
			if idx == 0 {
				hopRole = "Guard"
			} else if idx == len(c.Path)-1 {
				hopRole = "Exit"
			}
			fmt.Fprintf(out, "    Hop %d (%-6s) : %s (~%s)\n", idx+1, hopRole, hop.Fingerprint, hop.Nickname)
		}
		if len(c.BuildFlags) > 0 {
			fmt.Fprintf(out, "    Flags          : %s\n", strings.Join(c.BuildFlags, ", "))
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintln(out, "  CAUTION: Established circuits protect only streams routed to Tor SOCKS listeners.")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out)
	return nil
}

// RunTorEvents streams asynchronous Tor events for the specified duration.
func (a *Application) RunTorEvents(out io.Writer, duration time.Duration) error {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintf(out, "  TOR ASYNCHRONOUS EVENT STREAM (Duration: %v)\n", duration)
	fmt.Fprintln(out, "  Subscribing to: STATUS_CLIENT, CIRC")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")

	ctx, cancel := context.WithTimeout(context.Background(), duration+2*time.Second)
	defer cancel()

	client, err := a.getTorClient(ctx)
	if err != nil {
		fmt.Fprintf(out, "  Error: %v\n", err)
		fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
		return err
	}

	eventCh, err := client.SubscribeEvents(ctx, "STATUS_CLIENT", "CIRC")
	if err != nil {
		fmt.Fprintf(out, "  Failed to subscribe to events: %v\n", err)
		fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
		return err
	}

	fmt.Fprintln(out, "  Streaming events...")
	timer := time.NewTimer(duration)
	defer timer.Stop()

	received := 0
streamLoop:
	for {
		select {
		case evt, ok := <-eventCh:
			if !ok {
				break streamLoop
			}
			received++
			fmt.Fprintf(out, "  [%s] [%-12s] [%-6s] %s\n",
				evt.Timestamp.Format("15:04:05"),
				evt.Type,
				evt.Severity,
				evt.Raw,
			)
		case <-timer.C:
			break streamLoop
		}
	}

	if received == 0 {
		fmt.Fprintln(out, "  (No asynchronous events received during observation window)")
	}

	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out)
	return nil
}

// RunTorDiagnostics performs deep diagnostic inspection of the Tor subsystem.
func (a *Application) RunTorDiagnostics(out io.Writer) error {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out, "  TOR COMPREHENSIVE DIAGNOSTICS")
	fmt.Fprintln(out, "  Milestone 2 (M2) Native Tor Integration | Developed by 48sh1xbh")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")

	// 1. Configuration Check
	fmt.Fprintln(out, "  1. Configuration Settings:")
	fmt.Fprintf(out, "     • Enabled            : %t\n", a.Config.Tor.Enabled)
	fmt.Fprintf(out, "     • Network Mode       : %s\n", a.Config.Tor.NetworkMode)
	fmt.Fprintf(out, "     • Control Endpoint   : %s\n", a.Config.Tor.ControlEndpoint)
	fmt.Fprintf(out, "     • Connection Timeout : %v\n", a.Config.Tor.ConnectionTimeout)
	fmt.Fprintf(out, "     • Event Queue Limit  : %d\n", a.Config.Tor.EventQueueLimit)

	// 2. Binary in PATH check
	fmt.Fprintln(out, "\n  2. Host Tor Binary Discovery:")
	torPath, err := exec.LookPath("tor")
	if err != nil {
		torPath, err = exec.LookPath("tor.exe")
	}
	if err == nil {
		fmt.Fprintf(out, "     • Tor Executable     : DETECTED (%s)\n", torPath)
	} else {
		fmt.Fprintln(out, "     • Tor Executable     : NOT FOUND in PATH (Daemon may run as Windows Service or container)")
	}

	// 3. Polyglot Parser Component (pg-tor-inspector)
	fmt.Fprintln(out, "\n  3. Polyglot Rust Parser (pg-tor-inspector):")
	fmt.Fprintf(out, "     • Configured Path    : %s\n", a.Config.Tor.InspectorPath)
	bridge := tor.NewInspectorBridge(a.Config.Tor.InspectorPath, a.Config.Tor.InspectorTimeout)
	// Test bridge fallback / live parser
	testBootstrap := "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\n250 OK"
	parsedBoot, parseErr := bridge.ParseBootstrap(testBootstrap)
	if parseErr == nil && parsedBoot.Ready {
		fmt.Fprintln(out, "     • Parser Status      : OPERATIONAL (Self-test passed with Go revalidation)")
	} else {
		fmt.Fprintf(out, "     • Parser Status      : DEGRADED (%v)\n", parseErr)
	}

	// 4. Connection & Authentication
	fmt.Fprintln(out, "\n  4. ControlPort Verification:")
	ctx, cancel := context.WithTimeout(context.Background(), a.Config.Tor.ConnectionTimeout)
	defer cancel()

	client, err := a.getTorClient(ctx)
	if err != nil {
		fmt.Fprintf(out, "     • Control Connection : FAILED (%v)\n", err)
	} else {
		fmt.Fprintln(out, "     • Control Connection : ESTABLISHED (Loopback validated)")
		ver, _ := client.GetVersion(ctx)
		fmt.Fprintf(out, "     • Daemon Version     : %s\n", ver)

		monStatus := client.MonitoringStatus()
		fmt.Fprintf(out, "     • Monitoring Health  : %s (Dropped Events: %d, Total: %d)\n", monStatus.Health, monStatus.DroppedEvents, monStatus.TotalEvents)

		// 5. SOCKS listeners
		socks, err := client.GetSocksListeners(ctx)
		if err == nil && len(socks) > 0 {
			fmt.Fprintf(out, "     • SOCKS Listeners    : %s\n", strings.Join(socks, ", "))
		}
	}

	// 6. Semantic Privacy Check Results
	fmt.Fprintln(out, "\n  5. Privacy Engine Semantic Check Evaluation:")
	resAuth := a.Checker.CheckTorAuth()
	fmt.Fprintf(out, "     • %-22s: %s (%s)\n", resAuth.ID, resAuth.Status, resAuth.Summary)

	resBoot := a.Checker.CheckTorBootstrap()
	fmt.Fprintf(out, "     • %-22s: %s (%s)\n", resBoot.ID, resBoot.Status, resBoot.Summary)

	resCirc := a.Checker.CheckTorCircuitStatus()
	fmt.Fprintf(out, "     • %-22s: %s (%s)\n", resCirc.ID, resCirc.Status, resCirc.Summary)

	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out)
	return nil
}
