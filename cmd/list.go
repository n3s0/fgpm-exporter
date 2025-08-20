package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/jedib0t/go-pretty/v6/list"
)

var all bool
var hosts bool
var urls bool

var listCmd = &cobra.Command{
	Use: "list",
	Short: "List the firewall names and URLs available in the config file.",
	Long: `List the firewall names and URLs available in the config file.`,
	Run: func(cmd *cobra.Command, args []string) {
		if all {
			listAll()
		}

		if hosts {
			listHosts()
		}

		if urls {
			listUrls()
		}
	},
}

func init() {
	listCmd.Flags().BoolVarP(&all, "all", "a", false, "List all information, minus API keys.")
	listCmd.Flags().BoolVarP(&hosts, "hosts", "", false, "List the hosts in the configuration.")
	listCmd.Flags().BoolVarP(&urls, "urls", "", false, "List all urls within the configuration.")

	rootCmd.AddCommand(listCmd)
}

func listHosts() {
	lw := list.NewWriter()
	lw.SetOutputMirror(os.Stdout)
	lw.SetStyle(list.StyleConnectedBold)
	
	lw.AppendItem("Firewalls List:")
	lw.Indent()

	for _, host := range config.Hosts {
		name := fmt.Sprintf("Hostname: %s", host.Name)
		
		lw.AppendItem(name)
	}

	fmt.Printf("Listing available firewalls from configuration.\n\n")
	lw.Render()
}

func listUrls() {
	lw := list.NewWriter()
	lw.SetOutputMirror(os.Stdout)
	lw.SetStyle(list.StyleConnectedBold)
	
	lw.AppendItem("Firewalls List:")
	lw.Indent()

	for _, host := range config.Hosts {
		url := fmt.Sprintf("URL: %s", host.Url)
		
		lw.AppendItem(url)
	}

	fmt.Printf("Listing available firewalls from configuration.\n\n")
	lw.Render()
}

func listAll() {
	lw := list.NewWriter()
	lw.SetOutputMirror(os.Stdout)
	lw.SetStyle(list.StyleConnectedBold)
	
	lw.AppendItem("Firewalls List:")
	lw.Indent()

	for _, host := range config.Hosts {
		name := fmt.Sprintf("Hostname: %s", host.Name)
		url := fmt.Sprintf("URL: %s", host.Url)
		
		lw.AppendItem(name)
		lw.Indent()
		lw.AppendItem(url)
		lw.UnIndent()
	}

	fmt.Printf("Listing available firewalls from configuration.\n\n")
	lw.Render()
}

