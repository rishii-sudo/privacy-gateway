package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/rishii-sudo/privacy-gateway/internal/app"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	application, err := app.NewApplication("configs/default.yaml")
	if err != nil {
		return fmt.Errorf("initialization failure: %w", err)
	}
	defer application.Close()

	return runWithApp(args, application)
}

func runWithApp(args []string, application *app.Application) error {
	if len(args) == 0 {
		return application.RunInteractiveStartup(os.Stdin, os.Stdout)
	}

	firstArg := strings.ToLower(args[0])

	switch firstArg {
	case "--gui", "-gui":
		application.LaunchGUI(os.Stdout)
		return nil

	case "--cli", "-cli":
		scanner := bufio.NewScanner(os.Stdin)
		return application.RunInteractiveCLI(scanner, os.Stdout)

	case "--version", "-v", "version":
		application.ShowVersion(os.Stdout)
		return nil

	case "--diagnostics", "-d", "diagnostics":
		return application.RunDiagnostics(os.Stdout)

	case "--help", "-h", "help":
		app.ShowUsage(os.Stdout)
		return nil

	case "status":
		return application.RunStatus(os.Stdout)

	case "check":
		jsonOut := containsFlag(args[1:], "--json")
		return application.RunChecks(os.Stdout, jsonOut)

	case "report":
		jsonOut := containsFlag(args[1:], "--json")
		return application.RunReport(os.Stdout, jsonOut)

	case "tor":
		return application.RunTorCommand(os.Stdout, args[1:])

	default:
		fmt.Fprintf(os.Stdout, "Unknown command or flag: %s\n\n", firstArg)
		app.ShowUsage(os.Stdout)
		return nil
	}
}

func containsFlag(args []string, target string) bool {
	for _, a := range args {
		if strings.EqualFold(a, target) {
			return true
		}
	}
	return false
}
