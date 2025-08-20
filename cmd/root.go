/*
Copyright © 2025 NAME HERE tloftus@protonmail.com

*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var verbose bool

type Hosts struct {
	Name string `mapstructure:"name"`
	Url string `mapstructure:"url"`
	ApiKey string `mapstructure:"apikey"`
}

type Config struct {
	Hosts []Hosts `mapstructure:"hosts"`
}

var config Config

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "fgpm-exporter",
	Short: "Go commandline app for generating FortiSwitch portmaps using FortiGate API.",
	Long: `Go commandline app for generating FortiSwitch portmaps using the FortiGate API.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/fgpm-exporter/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "show more output to the console.")
	
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		viper.SetConfigType("yaml")
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("$HOME/.config/fgpm-exporter/")
		viper.AddConfigPath(".")
	}

	viper.AutomaticEnv()
	
	if err := viper.ReadInConfig(); err != nil {
		if verbose {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}
	}
	
	if err := viper.Unmarshal(&config); err != nil {
		if verbose {
			fmt.Printf("Error unmarshalling %s \n", err)
		}
	}
}
