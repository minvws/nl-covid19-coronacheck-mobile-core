package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/go-errors/errors"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	idemixverifier "github.com/minvws/nl-covid19-coronacheck-idemix/verifier"
	mobilecore "github.com/minvws/nl-covid19-coronacheck-mobile-core"
	"os"
)

func main() {
	availableCommandsMsg := "Available commands: verify, proofidentifier, commitments"

	// Subcommands
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	verifyConfigPath := verifyCmd.String("configdir", "./testdata", "Config directory to use")

	proofIdentifierCmd := flag.NewFlagSet("proofidentifier", flag.ExitOnError)
	proofIdentifierConfigPath := proofIdentifierCmd.String("configdir", "./testdata", "Config directory to use")

	commitmentsCmd := flag.NewFlagSet("commitments", flag.ExitOnError)
	issuerNonceBase64 := commitmentsCmd.String("prepare-issue-message", "", "Issuer nonce base64")
	commitmentsConfigPath := commitmentsCmd.String("configdir", "./testdata", "Config directory to use")

	if len(os.Args) < 2 {
		_, _ = fmt.Fprintln(os.Stderr, availableCommandsMsg)
		os.Exit(1)
	}

	switch os.Args[1] {
	case verifyCmd.Name():
		_ = verifyCmd.Parse(os.Args[2:])
	case commitmentsCmd.Name():
		_ = commitmentsCmd.Parse(os.Args[2:])
	case proofIdentifierCmd.Name():
		_ = proofIdentifierCmd.Parse(os.Args[2:])
	default:
		_, _ = fmt.Fprintln(os.Stderr, availableCommandsMsg)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if verifyCmd.Parsed() {
		err := runVerify(verifyCmd, verifyConfigPath)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}

	if proofIdentifierCmd.Parsed() {
		err := runProofIdentifier(proofIdentifierCmd, proofIdentifierConfigPath)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}

	if commitmentsCmd.Parsed() {
		err := runCommitments(commitmentsCmd, commitmentsConfigPath, issuerNonceBase64)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}
}

func runVerify(verifyFlags *flag.FlagSet, configPath *string) error {
	qr := verifyFlags.Arg(0)
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

	if verifyResult.Status == mobilecore.VERIFICATION_FAILED_UNRECOGNIZED_PREFIX {
		return errors.Errorf("Unrecognized QR prefix")
	}

	if verifyResult.Status == mobilecore.VERIFICATION_FAILED_IS_NL_DCC {
		return errors.Errorf("Is NL DCC")
	}

	verificationDetailsJson, err := json.Marshal(verifyResult.Details)
	if err != nil {
		return errors.WrapPrefix(err, "Could not JSON marshal verification details", 0)
	}

	fmt.Printf("Verification details: %s\n", verificationDetailsJson)
	return nil
}

func runProofIdentifier(pdFlags *flag.FlagSet, configPath *string) error {
	qr := []byte(pdFlags.Arg(0))
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

	// Get verifier, verify either the domestic or European QR code, and get the proof identifier
	domesticVerifier, europeanVerifier := mobilecore.GetVerifiersForCLI()

	var proofIdentifier []byte
	if idemixverifier.HasNLPrefix(qr) {
		verifiedCred, err := domesticVerifier.VerifyQREncoded(qr)
		if err != nil {
			return errors.WrapPrefix(err, "Could not verify domestic QR", 0)
		}

		proofIdentifier = verifiedCred.ProofIdentifier
		fmt.Printf("NL:")
	} else if hcertcommon.HasEUPrefix(qr) {
		verifiedQR, err := europeanVerifier.VerifyQREncoded(qr)
		if err != nil {
			return errors.WrapPrefix(err, "Could not verify european QR", 0)
		}

		proofIdentifier = verifiedQR.ProofIdentifier
		fmt.Printf("EU:")
	} else {
		return errors.Errorf("QR doesn't have EU or NL prefix")
	}

	proofIdentifierBase64 := base64.StdEncoding.EncodeToString(proofIdentifier)
	fmt.Printf("%s\n", proofIdentifierBase64)

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
