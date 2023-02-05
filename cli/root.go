package cli

import (
	"fmt"
	"os"

	"github.com/wokdav/gopki/generator/config"
	"github.com/wokdav/gopki/generator/db"
	"github.com/wokdav/gopki/generator/db/filesystem"
	"github.com/wokdav/gopki/logging"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gopki",
	Short: "Create complex PKI structures painlessly",
	Long: `gopki makes it easy to create complex certificate hierarchies
for testing.

However complex your PKI may be, gopki makes it easy to create
and maintain large certificate repositories. Certificate Profiles are easily
configured to ensure that your certificates conform to your standards.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if debug {
			logging.Initialize(logging.LevelDebug, nil, nil)
		} else if verbose {
			logging.Initialize(logging.LevelInfo, nil, nil)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

type signContext struct {
	genMissing     *bool
	genAll         *bool
	genExpired     *bool
	genNewerConfig *bool
}

var verbose bool
var debug bool

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "a LOT more verbose output (overrides -v)")

	ctx := signContext{}
	cmdSign := cobra.Command{
		Use:   "sign",
		Short: "(Re-)sign certificates",
		Long:  "Goes through a certificate folder, (re-)generating certificates as needed",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fsdb := filesystem.NewFilesystemDatabase(filesystem.NewNativeFs(args[0]))

			err := fsdb.Open()
			if err != nil {
				fmt.Printf("can't open as filesystem database: %s", err.Error())
				os.Exit(1)
			}

			defer fsdb.Close()

			//infer generation strategy
			var strat db.UpdateStrategy = db.UpdateNone

			if *ctx.genAll {
				strat |= db.UpdateAll
			}
			if *ctx.genMissing {
				strat |= db.UpdateMissing
			}
			if *ctx.genExpired {
				strat |= db.UpdateExpired
			}
			if *ctx.genNewerConfig {
				strat |= db.UpdateNewerConfig
			}

			if strat == db.UpdateNone {
				fmt.Println("all generate-flags set to false. nothing to do.")
				os.Exit(0)
			}

			err = fsdb.Update(strat)
			if err != nil {
				fmt.Printf("error during database update: %s", err.Error())
				os.Exit(1)
			}
		},
	}

	ctx.genMissing = cmdSign.PersistentFlags().BoolP("generate-missing", "m", true, "generate certificates if missing")
	ctx.genAll = cmdSign.PersistentFlags().BoolP("generate-all", "a", false, "(re-)generate all certificates")
	ctx.genExpired = cmdSign.PersistentFlags().BoolP("generate-expired", "e", false, "regenerate certificats if expired")
	ctx.genNewerConfig = cmdSign.PersistentFlags().BoolP("generate-outdated", "o", false, "regenerate certificates if config newer than certificates")

	cmdDoc := cobra.Command{
		Use:   "doc",
		Short: "Show Documentation",
		Long:  "Get help on various topics.",
	}

	cmdDoc.AddCommand(&cobra.Command{
		Use:       "example (profile|certificate)",
		Short:     "Show example config files",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"profile", "certificate"},
		Run: func(cmd *cobra.Command, args []string) {
			c, err := config.GetConfigurator(1)
			if err != nil {
				fmt.Println(err.Error())
			}
			switch args[0] {
			case "profile":
				fmt.Println(c.ProfileExample())
			case "certificate":
				fmt.Println(c.CertificateExample())
			default:
				fmt.Printf("Unknown example argument '%s'\n", args[0])
				cmdDoc.Help()
			}
		},
	})

	rootCmd.AddCommand(&cmdSign)
	rootCmd.AddCommand(&cmdDoc)
}
