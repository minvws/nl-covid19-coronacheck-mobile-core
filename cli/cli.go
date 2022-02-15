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
	"time"
)

func main() {
	availableCommandsMsg := "Available commands: verify, proofidentifier, commitments"

	// Subcommands
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	verifyConfigPath := verifyCmd.String("configdir", "./testdata", "Config directory to use")
	verifyTimestamp := verifyCmd.Int64("timestamp", time.Now().Unix(), "Timestamp of verification to use")
	verifyPolicy := verifyCmd.String("verificationpolicy", "3G", "Verification policy to use")

	proofIdentifierCmd := flag.NewFlagSet("proofidentifier", flag.ExitOnError)
	proofIdentifierConfigPath := proofIdentifierCmd.String("configdir", "./testdata", "Config directory to use")

	commitmentsCmd := flag.NewFlagSet("commitments", flag.ExitOnError)
	issueSpecificationMessage := commitmentsCmd.String("issue-specification-message", "", "Issue specification message")
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
		err := runVerify(verifyCmd, *verifyConfigPath, *verifyTimestamp, *verifyPolicy)
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
		err := runCommitments(commitmentsCmd, commitmentsConfigPath, issueSpecificationMessage)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}
}

func runVerify(verifyFlags *flag.FlagSet, configPath string, timestamp int64, givenVerificationPolicy string) error {
	// Make sure QR is given and config path exists
	qr := verifyFlags.Arg(0)
	if len(qr) == 0 {
		return errors.Errorf("No QR was given")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return errors.Errorf("Config directory '%s' does not exist\n", configPath)
	}

	// Choose the verification policy
	policies := map[string]string{
		"1G": mobilecore.VERIFICATION_POLICY_1G,
		"3G": mobilecore.VERIFICATION_POLICY_3G,
	}

	policy, ok := policies[givenVerificationPolicy]
	if !ok {
		return errors.Errorf("Unrecognized verification policy. Allowed values are: 1G, 3G")
	}

	// Initialization
	initializeResult := mobilecore.InitializeVerifier(configPath)
	if initializeResult.Error != "" {
		return errors.Errorf("Could not initialize verifier: %s\n", initializeResult.Error)
	}

	// Verify
	verifyResult := mobilecore.VerifyWithTime([]byte(qr), policy, timestamp)
	if verifyResult.Error != "" {
		return errors.Errorf("QR did not verify: %s\n", verifyResult.Error)
	}

	// Status checking
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

func runCommitments(commitments *flag.FlagSet, configPath *string, issueSpecificationMessageJson *string) error {
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		return errors.Errorf("Config directory '%s' does not exist\n", *configPath)
	}

	if *issueSpecificationMessageJson == "" {
		return errors.Errorf("No issue specification message JSON was provided")
	}

	initResult := mobilecore.InitializeHolder(*configPath)
	if initResult.Error != "" {
		return errors.Errorf("Could not initialize holder: %s", initResult.Error)
	}

	holderSkResult := mobilecore.GenerateHolderSk()
	if holderSkResult.Error != "" {
		return errors.Errorf("Could not generate holder sk: %s", holderSkResult.Error)
	}

	icmResult := mobilecore.CreateCommitmentMessage(holderSkResult.Value, []byte(*issueSpecificationMessageJson))
	if icmResult.Error != "" {
		return errors.Errorf("Could not create commitments: %s", icmResult.Error)
	}

	fmt.Println(string(icmResult.Value))
	return nil
}
