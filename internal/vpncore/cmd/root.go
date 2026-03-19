package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "tuncat-vpncore",
	Long: `A CLI application that supports the OpenConnect SSL VPN protocol.
For more information, please see the tuncat project documentation.`,
	CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() {
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
