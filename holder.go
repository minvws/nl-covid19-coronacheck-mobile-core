package mobilecore

import (
	"encoding/json"
	hcertholder "github.com/minvws/nl-covid19-coronacheck-hcert/holder"
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
)

const (
	DISCLOSURE_POLICY_1G = "1"
	DISCLOSURE_POLICY_3G = "3"
)

var (
	holderConfig *holderConfiguration

	domesticHolder *idemixholder.Holder
	europeanHolder *hcertholder.Holder

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
	publicKeysConfig, err := NewPublicKeysConfig(pksPath, false)
	if err != nil {
		return WrappedErrorResult(err, "Could not load public keys config")
	}

	// Initialize holders
	domesticHolder = idemixholder.New(publicKeysConfig.FindAndCacheDomestic, CREATE_CREDENTIAL_VERSION)
	europeanHolder = hcertholder.New()

	return &Result{nil, ""}
}

// DEPRECATED: See deprecation of LoadDomesticIssuerPks
var HasLoadedDomesticIssuerPks bool = false

// DEPRECATED: Remove this method when the mobile apps have migrated to using
//  InitializeHolder and the holder package directly
func LoadDomesticIssuerPks(annotatedPksJson []byte) *Result {
	holderConfig = &holderConfiguration{}

	// Unmarshal JSON list of keys
	annotatedPks := make([]*AnnotatedDomesticPk, 0)
	err := json.Unmarshal(annotatedPksJson, &annotatedPks)
	if err != nil {
		return WrappedErrorResult(err, "Could not unmarshal annotated issuer public keys")
	}

	// Transform legacy keys
	publicKeysConfig := &PublicKeysConfig{
		LegacyDomesticPks: annotatedPks,
	}
	publicKeysConfig.TransformLegacyDomesticPks()

	// Initialize holders
	domesticHolder = idemixholder.New(publicKeysConfig.FindAndCacheDomestic, CREATE_CREDENTIAL_VERSION)
	europeanHolder = hcertholder.New()

	// Set loaded status
	HasLoadedDomesticIssuerPks = true

	return &Result{nil, ""}
}
