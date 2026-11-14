package main

import (
	"os"

	"github.com/aj4ke/tunnelmtu/cmd"
	"github.com/spf13/cobra"
)

var version = "dev"

var rootCmd = &cobra.Command{
	Use:               "tunnelmtu",
	Short:             "L2TPv3 tunnel diagnostics",
	Version:           version,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
}

func init() {
	rootCmd.AddCommand(cmd.MTUCmd())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
