package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use: "version",
	Short: "Print the version number for fgpm-exporter",
	Long: `Print the version number for fgpm-exporter.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("FortiGate Port Map Exporter (fgpm-exporter) v1.2")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
