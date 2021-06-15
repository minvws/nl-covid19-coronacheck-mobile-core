package main

import (
	"flag"
	"fmt"
	mobilecore "github.com/minvws/nl-covid19-coronacheck-mobile-core"
	"os"
)

func main() {
	availableCommandsMsg := "Available commands: euqr"

	// Subcommands
	euqrCommand := flag.NewFlagSet("euqr", flag.ExitOnError)
	configPath := euqrCommand.String("configdir", "./testdata", "Config directory to use")

	if len(os.Args) < 2 {
		fmt.Println(availableCommandsMsg)
		os.Exit(1)
	}

	switch os.Args[1] {
	case euqrCommand.Name():
		_ = euqrCommand.Parse(os.Args[2:])
	default:
		fmt.Println(availableCommandsMsg)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if euqrCommand.Parsed() {
		qr := euqrCommand.Arg(0)
		if len(qr) == 0 {
			fmt.Println("No QR was given")
			os.Exit(1)
		}

		if _, err := os.Stat(*configPath); os.IsNotExist(err) {
			fmt.Printf("Config directory '%s' does not exist\n", *configPath)
			os.Exit(1)
		}

		initializeResult := mobilecore.InitializeVerifier(*configPath)
		if initializeResult.Error != "" {
			fmt.Printf("Could not initialize verifier: %s\n", initializeResult.Error)
			os.Exit(1)
		}

		verifyResult := mobilecore.Verify([]byte(qr))
		if verifyResult.Error != "" {
			fmt.Printf("QR did not verify: %s\n", verifyResult.Error)
			os.Exit(1)
		}

		fmt.Println(string(verifyResult.Value))
	}
}
