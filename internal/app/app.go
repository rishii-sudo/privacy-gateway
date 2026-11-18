package app

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
	"github.com/rishii-sudo/privacy-gateway/internal/logging"
	"github.com/rishii-sudo/privacy-gateway/internal/monitor"
	"github.com/rishii-sudo/privacy-gateway/internal/network"
	"github.com/rishii-sudo/privacy-gateway/internal/privacy"
	"github.com/rishii-sudo/privacy-gateway/internal/report"
)

const (
	Version   = "0.1.0-m1"
	Developer = "48sh1xbh"
)

// Application orchestrates core subsystems and user interfaces.
type Application struct {
	Config     *config.Config
	Logger     *logging.Logger
	Monitor    *monitor.SystemMonitor
	Enumerator *network.NetworkEnumerator
	Checker    *privacy.Checker
	startTime  time.Time
}

// NewApplication constructs and initializes core application subsystems from a config path.
func NewApplication(cfgPath string) (*Application, error) {
	cfg, err := config.LoadOrDefault(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}
	return NewApplicationWithConfig(cfg)
}

// NewApplicationWithConfig constructs core application subsystems using the provided Config.
func NewApplicationWithConfig(cfg *config.Config) (*Application, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	logger, err := logging.New(logging.Options{
		MinLevel:        logging.Level(cfg.Logging.Level),
		LogDir:          cfg.Storage.LogDir,
		Filename:        cfg.Logging.Filename,
		RecycleBinDir:   cfg.Storage.RecycleBinDir,
		LogToConsole:    false, // CLI manages direct user output
		LogToFile:       cfg.Logging.LogToFile,
		RedactSensitive: cfg.Logging.RedactSensitive,
		MaxBuffer:       1000,
	})
	if err != nil {
		return nil, fmt.Errorf("logging subsystem initialization failed: %w", err)
	}

	sysMonitor := monitor.New()
	enumerator := network.NewEnumerator(cfg.Network.VirtualInterfacePrefixes, cfg.Network.ProbeTimeout)
	checker := privacy.NewChecker(cfg)

	logger.Info(logging.CategorySystem, "Application", "Privacy Gateway initialized successfully")

	return &Application{
		Config:     cfg,
		Logger:     logger,
		Monitor:    sysMonitor,
		Enumerator: enumerator,
		Checker:    checker,
		startTime:  time.Now().UTC(),
	}, nil
}

// Close gracefully flushes and releases application resources.
func (a *Application) Close() error {
	if a.Logger != nil {
		return a.Logger.Close()
	}
	return nil
}

// RunInteractiveStartup presents the master interactive startup menu.
func (a *Application) RunInteractiveStartup(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)

	for {
		fmt.Fprintln(out, "PRIVACY GATEWAY")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Welcome to Privacy Gateway.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Select your interface:")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "[1] GUI Mode")
		fmt.Fprintln(out, "[2] CLI Mode")
		fmt.Fprintln(out, "[3] System Diagnostics")
		fmt.Fprintln(out, "[4] Exit")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Developed by 48sh1xbh")
		fmt.Fprintln(out)
		fmt.Fprint(out, "> ")

		if !scanner.Scan() {
			break
		}

		choice := strings.TrimSpace(scanner.Text())
		switch choice {
		case "1":
			a.LaunchGUI(out)
		case "2":
			return a.RunInteractiveCLI(scanner, out)
		case "3":
			if err := a.RunDiagnostics(out); err != nil {
				fmt.Fprintf(out, "Diagnostics error: %v\n\n", err)
			}
		case "4":
			fmt.Fprintln(out, "Exiting Privacy Gateway. Stay safe.")
			return nil
		default:
			fmt.Fprintln(out, "Invalid selection. Please choose an option from 1 to 4.")
		}
	}
	return scanner.Err()
}

// LaunchGUI handles the GUI mode invocation.
func (a *Application) LaunchGUI(out io.Writer) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out, "  DESKTOP GUI INTERFACE")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out, "  The React/TypeScript desktop GUI is scheduled for Milestone 9 (M9).")
	fmt.Fprintln(out, "  In Milestone 1, full functionality is available via CLI Mode.")
	fmt.Fprintln(out, "  Run 'privacy-gateway --cli' or select [2] for terminal operations.")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out)
}

// RunInteractiveCLI provides an interactive shell for privacy operations.
func (a *Application) RunInteractiveCLI(scanner *bufio.Scanner, out io.Writer) error {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "==============================================================================")
	fmt.Fprintln(out, "  PRIVACY GATEWAY CLI INTERFACE")
	fmt.Fprintln(out, "  Type 'help' for available commands, or 'exit' to return.")
	fmt.Fprintln(out, "==============================================================================")
	fmt.Fprintln(out)

	for {
		fmt.Fprint(out, "pg-cli> ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "exit", "quit":
			fmt.Fprintln(out, "Returning to main menu...")
			return a.RunInteractiveStartup(os.Stdin, out)
		case "status":
			_ = a.RunStatus(out)
		case "check":
			_ = a.RunChecks(out, false)
		case "report":
			jsonOut := len(parts) > 1 && parts[1] == "--json"
			_ = a.RunReport(out, jsonOut)
		case "diagnostics":
			_ = a.RunDiagnostics(out)
		case "logs":
			a.showRecentLogs(out)
		case "recycle":
			a.showRecycledLogs(out)
		case "help":
			a.ShowCLIHelp(out)
		default:
			fmt.Fprintf(out, "Unknown command %q. Type 'help' for available commands.\n", cmd)
		}
		fmt.Fprintln(out)
	}
	return scanner.Err()
}

// RunDiagnostics executes comprehensive read-only system and network diagnostics.
func (a *Application) RunDiagnostics(out io.Writer) error {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out, "  SYSTEM & NETWORK DIAGNOSTICS")
	fmt.Fprintln(out, "  Developed by 48sh1xbh | Read-Only Discovery")
	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")

	sysInfo, err := a.Monitor.GetSystemInfo()
	if err != nil {
		return fmt.Errorf("system info query failed: %w", err)
	}

	sysHealth, err := a.Monitor.GetSystemHealth()
	if err != nil {
		return fmt.Errorf("system health query failed: %w", err)
	}

	fmt.Fprintf(out, "  Host:             %s\n", sysInfo.Hostname)
	fmt.Fprintf(out, "  OS / Arch:        %s / %s\n", sysInfo.OS, sysInfo.Arch)
	fmt.Fprintf(out, "  Go Version:       %s\n", sysInfo.GoVersion)
	fmt.Fprintf(out, "  CPU Cores:        %d\n", sysInfo.NumCPU)
	fmt.Fprintf(out, "  PID:              %d\n", sysInfo.ProcessID)
	fmt.Fprintf(out, "  Uptime:           %s\n", monitor.FormatUptime(a.startTime))
	fmt.Fprintf(out, "  Memory Allocated: %d KB\n", sysHealth.MemoryAllocated/1024)
	fmt.Fprintf(out, "  Memory Sys:       %d KB\n", sysHealth.MemorySys/1024)
	fmt.Fprintf(out, "  Health Status:    %s\n", sysHealth.Status)
	fmt.Fprintf(out, "  UTC Timestamp:    %s\n", sysInfo.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintln(out, "──────────────────────────────────────────────────────────────────────────────")
	fmt.Fprintln(out, "  NETWORK INTERFACES (READ-ONLY ENUMERATION):")

	ifaces, err := a.Enumerator.EnumerateInterfaces()
	if err != nil {
		return fmt.Errorf("network discovery failed: %w", err)
	}

	for _, iface := range ifaces {
		statusStr := "DOWN"
		if iface.IsUp {
			statusStr = "UP"
		}
		descStr := ""
		if iface.Description != "" && iface.Description != iface.Name {
			descStr = fmt.Sprintf(" (%s)", iface.Description)
		}
		fmt.Fprintf(out, "  • [%s] %-16s Type: %-22s MTU: %-5d MAC: %s%s\n",
			statusStr, iface.Name, iface.Type, iface.MTU, iface.RedactedMAC, descStr)
		for _, addr := range iface.Addresses {
			fmt.Fprintf(out, "      └─ %s (%s, private=%v)\n", addr.CIDR, addr.Family, addr.IsPrivate)
		}
	}

	fmt.Fprintln(out, "──────────────────────────────────────────────────────────────────────────────")
	dnsCfg := network.DiscoverDNSResolvers(a.Config.Network.DnsServers)
	fmt.Fprintf(out, "  DNS Resolvers:    %s (Source: %s)\n", strings.Join(dnsCfg.Servers, ", "), dnsCfg.Source)

	// Local routing candidate
	candidate, err := a.Enumerator.DiscoverOutboundCandidate("")
	if err == nil {
		fmt.Fprintf(out, "  Outbound Route:   Local IP %s via interface %s\n", candidate.LocalIP, candidate.InterfaceName)
	}

	fmt.Fprintln(out, "══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out)
	return nil
}

// RunStatus reports application, monitor and engine status summary.
func (a *Application) RunStatus(out io.Writer) error {
	sysHealth, err := a.Monitor.GetSystemHealth()
	if err != nil {
		return err
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "Privacy Gateway [%s] | %s\n", Version, Developer)
	fmt.Fprintf(out, "Environment:       %s\n", a.Config.App.Environment)
	fmt.Fprintf(out, "Engine Health:     %s\n", sysHealth.Status)
	fmt.Fprintf(out, "Active Interfaces: %d\n", sysHealth.ActiveInterfaces)
	fmt.Fprintf(out, "Firewall Policy:   %s mode\n", a.Config.Firewall.Mode)
	fmt.Fprintf(out, "Telemetry:         disabled (local-only processing)\n")
	fmt.Fprintf(out, "Log Path:          %s/%s\n", a.Config.Storage.LogDir, a.Config.Logging.Filename)
	fmt.Fprintln(out)
	return nil
}

// RunChecks executes baseline privacy checks and prints results.
func (a *Application) RunChecks(out io.Writer, jsonOutput bool) error {
	checks, err := a.Checker.RunAllBaselineChecks()
	if err != nil {
		return fmt.Errorf("failed to execute privacy checks: %w", err)
	}

	sysInfo, _ := a.Monitor.GetSystemInfo()
	sysHealth, _ := a.Monitor.GetSystemHealth()
	rep := report.NewAuditReport(sysInfo, sysHealth, checks)

	if jsonOutput {
		data, err := rep.ToJSON()
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprint(out, report.FormatTerminal(rep))
	return nil
}

// RunReport executes checks, formats report, and saves a JSON copy in Reports/.
func (a *Application) RunReport(out io.Writer, jsonOutput bool) error {
	checks, err := a.Checker.RunAllBaselineChecks()
	if err != nil {
		return fmt.Errorf("audit check execution failed: %w", err)
	}

	sysInfo, _ := a.Monitor.GetSystemInfo()
	sysHealth, _ := a.Monitor.GetSystemHealth()
	rep := report.NewAuditReport(sysInfo, sysHealth, checks)

	savedPath, err := rep.SaveJSON(a.Config.Storage.ReportDir)
	if err != nil {
		a.Logger.Error(logging.CategoryErrors, "Report", fmt.Sprintf("Failed to save report: %v", err))
	} else {
		a.Logger.Info(logging.CategoryAudit, "Report", fmt.Sprintf("Report saved: %s", savedPath))
	}

	if jsonOutput {
		data, err := rep.ToJSON()
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprint(out, report.FormatTerminal(rep))
	if savedPath != "" {
		fmt.Fprintf(out, "  [i] JSON report written to: %s\n\n", savedPath)
	}
	return nil
}

func (a *Application) showRecentLogs(out io.Writer) {
	fmt.Fprintln(out, "\n  RECENT APPLICATION LOGS:")
	entries := a.Logger.Search(logging.LogFilter{})
	if len(entries) == 0 {
		fmt.Fprintln(out, "  (No logs recorded yet)")
		return
	}

	start := 0
	if len(entries) > 20 {
		start = len(entries) - 20
	}
	for _, e := range entries[start:] {
		fmt.Fprintf(out, "  [%s] [%-5s] [%-10s] %s\n",
			e.Timestamp.Format("15:04:05"), e.Level, e.Category, e.Message)
	}
}

func (a *Application) showRecycledLogs(out io.Writer) {
	list, err := a.Logger.ListRecycledLogs()
	if err != nil {
		fmt.Fprintf(out, "Error reading Recycle Bin: %v\n", err)
		return
	}
	fmt.Fprintf(out, "\n  RECYCLED LOGS IN '%s' (%d files):\n", a.Config.Storage.RecycleBinDir, len(list))
	for _, f := range list {
		fmt.Fprintf(out, "  • %s\n", f)
	}
	if len(list) == 0 {
		fmt.Fprintln(out, "  (Recycle bin is clean)")
	}
}

// ShowVersion displays version and developer attribution.
func (a *Application) ShowVersion(out io.Writer) {
	fmt.Fprintf(out, "Privacy Gateway version %s\n", Version)
	fmt.Fprintf(out, "Developed by %s\n", Developer)
}

// ShowCLIHelp displays available CLI commands and flags.
func (a *Application) ShowCLIHelp(out io.Writer) {
	fmt.Fprintln(out, "Available CLI commands:")
	fmt.Fprintln(out, "  status        Display application and privacy engine status")
	fmt.Fprintln(out, "  check         Run all baseline privacy and security verification checks")
	fmt.Fprintln(out, "  report        Generate detailed audit report (add --json for JSON format)")
	fmt.Fprintln(out, "  diagnostics   Perform read-only system and network diagnostics")
	fmt.Fprintln(out, "  logs          View recent structured logs")
	fmt.Fprintln(out, "  recycle       List archived log files in Recycle Bin")
	fmt.Fprintln(out, "  help          Show this command reference")
	fmt.Fprintln(out, "  exit          Return to main menu")
}

// ShowUsage displays top-level command-line usage.
func ShowUsage(out io.Writer) {
	fmt.Fprintln(out, "PRIVACY GATEWAY")
	fmt.Fprintln(out, "Developed by 48sh1xbh")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  privacy-gateway              Launch interactive startup menu")
	fmt.Fprintln(out, "  privacy-gateway --gui        Launch GUI Mode")
	fmt.Fprintln(out, "  privacy-gateway --cli        Launch CLI Mode")
	fmt.Fprintln(out, "  privacy-gateway --version    Display version information")
	fmt.Fprintln(out, "  privacy-gateway --diagnostics Run system diagnostics")
	fmt.Fprintln(out, "  privacy-gateway --help       Display this help message")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Subcommands:")
	fmt.Fprintln(out, "  privacy-gateway status       Display system status")
	fmt.Fprintln(out, "  privacy-gateway check        Execute all privacy verification checks")
	fmt.Fprintln(out, "  privacy-gateway report       Generate security audit report (--json for JSON)")
	fmt.Fprintln(out, "  privacy-gateway diagnostics  Run system diagnostics")
}
