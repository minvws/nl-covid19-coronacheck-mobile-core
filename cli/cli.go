package main

import (
	"flag"
	"fmt"
	"github.com/go-errors/errors"
	mobilecore "github.com/minvws/nl-covid19-coronacheck-mobile-core"
	"os"
)

func main() {
	availableCommandsMsg := "Available commands: euqr, commitments"

	// Subcommands
	euqrCmd := flag.NewFlagSet("euqr", flag.ExitOnError)
	euqrConfigPath := euqrCmd.String("configdir", "./testdata", "Config directory to use")

	commitmentsCmd := flag.NewFlagSet("commitments", flag.ExitOnError)
	issuerNonceBase64 := commitmentsCmd.String("prepare-issue-message", "", "Issuer nonce base64")
	commitmentsConfigPath := commitmentsCmd.String("configdir", "./testdata", "Config directory to use")

	if len(os.Args) < 2 {
		fmt.Println(availableCommandsMsg)
		os.Exit(1)
	}

	switch os.Args[1] {
	case euqrCmd.Name():
		_ = euqrCmd.Parse(os.Args[2:])
	case commitmentsCmd.Name():
		_ = commitmentsCmd.Parse(os.Args[2:])
	default:
		fmt.Println(availableCommandsMsg)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if euqrCmd.Parsed() {
		err := runEUQR(euqrCmd, euqrConfigPath)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}

	if commitmentsCmd.Parsed() {
		err := runCommitments(commitmentsCmd, commitmentsConfigPath, issuerNonceBase64)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}
}

func runEUQR(euqr *flag.FlagSet, configPath *string) error {
	qr := euqr.Arg(0)
	if len(qr) == 0 {
		return errors.Errorf("No QR was given")
	}

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		return errors.Errorf("Config directory '%s' does not exist\n", *configPath)
	}

	initializeResult := mobilecore.InitializeVerifier(*configPath)
	if initializeResult.Error != "" {
		return errors.Errorf("Could not initialize verifier: %s\n", initializeResult.Error)
	}

	verifyResult := mobilecore.Verify([]byte(qr))
	if verifyResult.Error != "" {
		return errors.Errorf("QR did not verify: %s\n", verifyResult.Error)
	}

	fmt.Println(string(verifyResult.Value))
	return nil
}

func runCommitments(commitments *flag.FlagSet, configPath *string, prepareIssueMessageJson *string) error {
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		return errors.Errorf("Config directory '%s' does not exist\n", *configPath)
	}

	if *prepareIssueMessageJson == "" {
		return errors.Errorf("No prepare issue message JSON was provided")
	}

	initResult := mobilecore.InitializeHolder(*configPath)
	if initResult.Error != "" {
		return errors.Errorf("Could not initialize holder: %s", initResult.Error)
	}

	holderSkResult := mobilecore.GenerateHolderSk()
	if holderSkResult.Error != "" {
		return errors.Errorf("Could not generate holder sk: %s", holderSkResult.Error)
	}

	icmResult := mobilecore.CreateCommitmentMessage(holderSkResult.Value, []byte(*prepareIssueMessageJson))
	if icmResult.Error != "" {
		return errors.Errorf("Could not create commitments: %s", icmResult.Error)
	}

	fmt.Println(string(icmResult.Value))
	return nil
}
