package main

import (
	"flag"
	"fmt"

	"github.com/xoxproxy/xoxproxy/internal/buildinfo"
	"github.com/xoxproxy/xoxproxy/internal/config"
)

func versionString() string {
	return buildinfo.String()
}

// runConfig dispatches "xoxproxy config <subcommand>". It is intentionally
// separate from the server so operators can validate a candidate file
// before it is ever loaded by the running service.
func runConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("config: no subcommand given (try \"xoxproxy config validate\")")
	}
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
		cfgPath := configFlag(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		path := resolveConfigPath(fs, cfgPath)
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		fmt.Printf("OK %s\n", path)
		fmt.Printf("  server.listen    %s\n", cfg.Server.Listen)
		fmt.Printf("  engine.provider  %s\n", cfg.Engine.Provider)
		fmt.Printf("  proxy.http       %d\n", cfg.Proxy.HTTPPort)
		fmt.Printf("  proxy.socks5     %d\n", cfg.Proxy.SOCKS5Port)
		fmt.Printf("  database.path    %s\n", cfg.Database.Path)
		return nil
	default:
		return fmt.Errorf("config: unknown subcommand %q", args[0])
	}
}
