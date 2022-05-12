package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/go-errors/errors"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	idemixcommon "github.com/minvws/nl-covid19-coronacheck-idemix/common"
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

	explainCmd := flag.NewFlagSet("explain", flag.ExitOnError)
	explainConfigPath := explainCmd.String("configdir", "./testdata", "Config directory to use")
	explainTimestamp := explainCmd.Int64("timestamp", time.Now().Unix(), "Timestamp of verification to use")

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
	case explainCmd.Name():
		_ = explainCmd.Parse(os.Args[2:])
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

	if explainCmd.Parsed() {
		err := runExplain(explainCmd, *explainConfigPath, *explainTimestamp)
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
	if idemixcommon.HasNLPrefix(qr) {
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

func runExplain(explainFlags *flag.FlagSet, configPath string, timestamp int64) error {
	// Make sure QR is given and config path exists
	qr := []byte(explainFlags.Arg(0))
	if len(qr) == 0 {
		return errors.Errorf("No QR was given")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return errors.Errorf("Config directory '%s' does not exist\n", configPath)
	}

	// Initialization
	initializeResult := mobilecore.InitializeVerifier(configPath)
	if initializeResult.Error != "" {
		return errors.Errorf("Could not initialize verifier: %s\n", initializeResult.Error)
	}

	_, europeanVerifier := mobilecore.GetVerifiersForCLI()

	if idemixcommon.HasNLPrefix(qr) {
		fmt.Println("Recognized as QR-code with Dutch prefix")
		fmt.Println("Explain is not implemented for Dutch QR codes yet")

	} else if hcertcommon.HasEUPrefix(qr) {
		fmt.Println("\nRecognized as QR-code with European prefix")

		verified, err := europeanVerifier.VerifyQREncoded(qr)
		if err != nil {
			return errors.WrapPrefix(err, "QR-code signature verification failed:", 0)
		}

		kid := base64.StdEncoding.EncodeToString(verified.PublicKey.SubjectPk)[:8]
		fmt.Printf(
			"Successfully verified DCC with key with key id '%s' (IAN '%s', SAN '%s')\n",
			kid, verified.PublicKey.IssuerAltName, verified.PublicKey.SubjectAltName,
		)

		dcc := verified.HealthCertificate.DCC
		fmt.Printf("\nCWT: %+v\n", verified.HealthCertificate)
		fmt.Printf("DCC: %+v\n", dcc)
		fmt.Printf("Name: %+v\n", dcc.Name)

		if len(dcc.Vaccinations) > 0 {
			fmt.Printf("Vaccination: %+v\n", dcc.Vaccinations[0])
		}

		if len(dcc.Recoveries) > 0 {
			fmt.Printf("Recovery: %+v\n", dcc.Recoveries[0])
		}

		if len(dcc.Tests) > 0 {
			fmt.Printf("Negative test: %+v\n", dcc.Tests[0])
		}

		pretty, err := json.MarshalIndent(verified.HealthCertificate, "", "  ")
		if err != nil {
			return errors.WrapPrefix(err, "Could not pretty print DCC contents", 0)
		}

		fmt.Println("\nJSON representation:")
		fmt.Println(string(pretty))

		for policyStr, policy := range policies {
			fmt.Printf("\nVerifying with %s policy: \n", policyStr)

			// Verify
			verifyResult := mobilecore.VerifyWithTime([]byte(qr), policy, timestamp)
			if verifyResult.Error != "" {
				fmt.Printf("QR did not verify: %s\n", verifyResult.Error)
				continue
			}

			// Status checking
			if verifyResult.Status == mobilecore.VERIFICATION_FAILED_UNRECOGNIZED_PREFIX {
				fmt.Printf("Unrecognized QR prefix")
				continue
			}

			if verifyResult.Status == mobilecore.VERIFICATION_FAILED_IS_NL_DCC {
				fmt.Printf("Would not verify because this is an NL DCC")
				continue
			}

			verificationDetailsJson, err := json.Marshal(verifyResult.Details)
			if err != nil {
				return errors.WrapPrefix(err, "Could not JSON marshal verification details", 0)
			}

			fmt.Printf("Verification details for policy %s: %s\n", policyStr, verificationDetailsJson)
		}

	} else {
		fmt.Println("QR-code not recognized as Dutch or European")
	}

	return nil
}

var policies = map[string]string{
	"1G": mobilecore.VERIFICATION_POLICY_1G,
	"3G": mobilecore.VERIFICATION_POLICY_3G,
}
