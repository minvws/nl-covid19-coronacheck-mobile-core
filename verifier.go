package mobilecore

import (
	"encoding/json"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	hcertverifier "github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	idemixverifier "github.com/minvws/nl-covid19-coronacheck-idemix/verifier"
	"os"
	"path"
)

const (
	VERIFIER_CONFIG_FILENAME      = "config.json"
	VERIFIER_PUBLIC_KEYS_FILENAME = "public_keys.json"
)

type verifierConfiguration struct {
	// Until business rules are part of the config, we don't need anything from here
}

var (
	verifierConfig *verifierConfiguration

	domesticVerifier *idemixverifier.Verifier
	europeanVerifier *hcertverifier.Verifier
)

// DEPRECATED: Remove this function once the mobile apps handle
//  the (error) result and panic until then
func InitializeVerifier(configDirectoryPath string) {
	res := ActualInitializeVerifier(configDirectoryPath)
	if res.Error != "" {
		panic(res.Error)
	}
}

func ActualInitializeVerifier(configDirectoryPath string) *Result {
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
	var attributes interface{}
	var err error

	if hcertcommon.HasEUPrefix(proofQREncoded) {
		attributes, err = verifyEuropean(proofQREncoded)
		if err != nil {
			return WrappedErrorResult(err, "Could not verify European QR code")
		}
	} else {
		attributes, err = verifyDomestic(proofQREncoded)
		if err != nil {
			return WrappedErrorResult(err, "Could not verify domestic QR code")
		}
	}

	attributesJson, err := json.Marshal(attributes)
	if err != nil {
		return WrappedErrorResult(err, "Could not JSON marshal verified attributes")
	}

	return &Result{attributesJson, ""}
}
