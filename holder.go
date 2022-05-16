package mobilecore

import (
	"encoding/json"
	hcertholder "github.com/minvws/nl-covid19-coronacheck-hcert/holder"
	hcertverifier "github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	idemixholder "github.com/minvws/nl-covid19-coronacheck-idemix/holder"
	"github.com/privacybydesign/gabi"
	"os"
	"path"
)

const (
	HOLDER_CONFIG_FILENAME      = "config.json"
	HOLDER_PUBLIC_KEYS_FILENAME = "public_keys.json"
	CREATE_CREDENTIAL_VERSION   = 3

	DCC_DOMESTIC_ISSUER_COUNTRY_CODE = "NL"
	DCC_DOMESTIC_ISSUER_KEY_SAN      = "NLD"
)

const (
	DISCLOSURE_POLICY_1G = "1"
	DISCLOSURE_POLICY_3G = "3"
)

var (
	holderConfig *holderConfiguration

	domesticHolder *idemixholder.Holder
	europeanHolder *hcertholder.Holder

	// euopeanPksLookup is only used to determine key SAN for CAS-islands
	europeanPksLookup hcertverifier.PksLookup

	lastCredBuilders []gabi.ProofBuilder
)

type holderConfiguration struct {
	// Until business rules are part of the config, we don't need anything from here
}

func InitializeHolder(configDirectoryPath string) *Result {
	configPath := path.Join(configDirectoryPath, HOLDER_CONFIG_FILENAME)
	pksPath := path.Join(configDirectoryPath, HOLDER_PUBLIC_KEYS_FILENAME)

	// Load config
	configJson, err := os.ReadFile(configPath)
	if err != nil {
		return WrappedErrorResult(err, "Could not read holder config file")
	}

	err = json.Unmarshal(configJson, &holderConfig)
	if err != nil {
		return WrappedErrorResult(err, "Could not JSON unmarshal holder config")
	}

	// Read public keys
	publicKeysConfig, err := NewPublicKeysConfig(pksPath)
	if err != nil {
		return WrappedErrorResult(err, "Could not load public keys config")
	}

	// Initialize holders
	domesticHolder = idemixholder.New(publicKeysConfig.FindAndCacheDomestic, CREATE_CREDENTIAL_VERSION)
	europeanHolder = hcertholder.New()
	europeanPksLookup = publicKeysConfig.EuropeanPks

	return &Result{nil, ""}
}
