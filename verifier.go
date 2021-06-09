package mobilecore

import (
	"encoding/json"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	hcertverifier "github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	idemixverifier "github.com/minvws/nl-covid19-coronacheck-idemix/verifier"
	"os"
	"path"
	"time"
)

const (
	VERIFIER_CONFIG_FILENAME      = "config.json"
	VERIFIER_PUBLIC_KEYS_FILENAME = "public_keys.json"
)

// VerificationResult very much mimics the domestic verifier attributes, with only string type values,
//  to minimize app-side changes. In the future, both should return properly typed values.
type VerificationResult struct {
	CredentialVersion string `json:"credentialVersion"`
	IsSpecimen        string `json:"isSpecimen"`
	FirstNameInitial  string `json:"firstNameInitial"`
	LastNameInitial   string `json:"lastNameInitial"`
	BirthDay          string `json:"birthDay"`
	BirthMonth        string `json:"birthMonth"`

	IsNLDCC string `json:"isNLDCC"`
}

type verifierConfiguration struct {
	// Until business rules are part of the config, we don't need anything from here
}

var (
	verifierConfig *verifierConfiguration

	domesticVerifier *idemixverifier.Verifier
	europeanVerifier *hcertverifier.Verifier
)

func InitializeVerifier(configDirectoryPath string) *Result {
	configPath := path.Join(configDirectoryPath, VERIFIER_CONFIG_FILENAME)
	pksPath := path.Join(configDirectoryPath, VERIFIER_PUBLIC_KEYS_FILENAME)

	// Load config
	configJson, err := os.ReadFile(configPath)
	if err != nil {
		return WrappedErrorResult(err, "Could not read verifier config file")
	}

	err = json.Unmarshal(configJson, &verifierConfig)
	if err != nil {
		return WrappedErrorResult(err, "Could not JSON unmarshal verifier config")
	}

	// Read public keys
	publicKeysConfig, err := NewPublicKeysConfig(pksPath, true)
	if err != nil {
		return WrappedErrorResult(err, "Could not load public keys config")
	}

	// Initialize verifiers
	domesticVerifier = idemixverifier.New(publicKeysConfig.FindAndCacheDomestic)
	europeanVerifier = hcertverifier.New(publicKeysConfig.FindAndCacheEuropean)

	return &Result{nil, ""}
}

func Verify(proofQREncoded []byte) *Result {
	return verify(proofQREncoded, time.Now())
}

func verify(proofQREncoded []byte, now time.Time) *Result {
	var verificationResult *VerificationResult
	var err error

	if hcertcommon.HasEUPrefix(proofQREncoded) {
		verificationResult, err = verifyEuropean(proofQREncoded, now)
		if err != nil {
			return WrappedErrorResult(err, "Could not verify European QR code")
		}
	} else {
		verificationResult, err = verifyDomestic(proofQREncoded, now)
		if err != nil {
			return WrappedErrorResult(err, "Could not verify domestic QR code")
		}
	}

	verificationResultJson, err := json.Marshal(verificationResult)
	if err != nil {
		return WrappedErrorResult(err, "Could not JSON marshal verified attributes")
	}

	return &Result{verificationResultJson, ""}
}
