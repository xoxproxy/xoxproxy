// Command xoxproxy is the control-plane server and administrative CLI.
//
// Subcommands share the service layer with the HTTP API; this file only
// dispatches. Usage:
//
//	xoxproxy server  [-config PATH]
//	xoxproxy config  validate [-config PATH]
//	xoxproxy version
//	xoxproxy help
package main

import (
	"context"
	"fmt"
	"os"
)

const usageText = `xoxproxy — proxy management control plane

Usage:
  xoxproxy <command> [flags]

Commands:
  server           start the control plane (API, dashboard, background jobs)
  config validate  validate a configuration file and print the result
  admin            manage administrators (create, reset-password)
  users            manage proxy users (list, create, disable, enable, rotate-password)
  deploy           reconcile the engine config with the store now
  version          print version information
  help             show this help

Flags are documented per command; run "xoxproxy <command> -help".
The configuration file path defaults to $XOXPROXY_CONFIG or
` + "`/etc/xoxproxy/config.toml`" + `.`

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "xoxproxy: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return fmt.Errorf("no command given")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "server":
		return runServer(ctx, rest)
	case "config":
		return runConfig(rest)
	case "admin":
		return runAdmin(ctx, rest)
	case "users":
		return runUsers(ctx, rest)
	case "deploy":
		return runDeploy(ctx, rest)
	case "version", "--version", "-v":
		fmt.Println(versionString())
		return nil
	case "help", "--help", "-h":
		fmt.Print(usageText)
		return nil
	default:
		return fmt.Errorf("unknown command %q — run \"xoxproxy help\"", cmd)
	}
}
