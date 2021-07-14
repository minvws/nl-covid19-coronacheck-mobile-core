package mobilecore

import (
	"encoding/json"
	"github.com/go-errors/errors"
	hcertverifier "github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	"github.com/privacybydesign/gabi"
	"os"
)

type PublicKeysConfig struct {
	DomesticPks DomesticPksLookup               `json:"nl_keys"`
	EuropeanPks hcertverifier.EuropeanPksLookup `json:"eu_keys"`

	// DEPRECATED: Remove this struct when the transition to nl_keys is complete
	LegacyDomesticPks []*AnnotatedDomesticPk `json:"cl_keys"`
}

type DomesticPksLookup map[string]*AnnotatedDomesticPk

type AnnotatedDomesticPk struct {
	PkXml    []byte          `json:"public_key"`
	LoadedPk *gabi.PublicKey `json:"-"`

	// DEPRECATED: Remove this field together with LegacyDomesticPks
	KID string `json:"id"`
}

func NewPublicKeysConfig(pksPath string, expectEuropeanKeys bool) (*PublicKeysConfig, error) {
	pksJson, err := os.ReadFile(pksPath)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not read public keys file", 0)
	}

	var publicKeysConfig *PublicKeysConfig
	err = json.Unmarshal(pksJson, &publicKeysConfig)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not JSON unmarshal public keys", 0)
	}

	publicKeysConfig.TransformLegacyDomesticPks()

	if publicKeysConfig.DomesticPks == nil {
		return nil, errors.Errorf("No domestic keys map was present")
	}

	if expectEuropeanKeys && publicKeysConfig.EuropeanPks == nil {
		return nil, errors.Errorf("No european keys map was present")
	}

	return publicKeysConfig, nil
}

// DEPRECATED: Remove this legacy transformation together with LegacyDomesticPks
func (pkc *PublicKeysConfig) TransformLegacyDomesticPks() {
	if pkc.DomesticPks == nil && pkc.LegacyDomesticPks != nil {
		pkc.DomesticPks = DomesticPksLookup{}
		for _, ldpk := range pkc.LegacyDomesticPks {
			pkc.DomesticPks[ldpk.KID] = &AnnotatedDomesticPk{
				PkXml: ldpk.PkXml,
			}
		}
	}
}

func (pkc *PublicKeysConfig) FindAndCacheDomestic(kid string) (*gabi.PublicKey, error) {
	// Check if key id is present
	annotatedPk, ok := pkc.DomesticPks[kid]
	if !ok {
		return nil, errors.Errorf("Could not find domestic public key")
	}

	// Ensure the public key is cached
	if annotatedPk.LoadedPk == nil {
		var err error
		annotatedPk.LoadedPk, err = gabi.NewPublicKeyFromBytes(annotatedPk.PkXml)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not XML unmarshal and load domestic issuer public key", 0)
		}
	}

	return annotatedPk.LoadedPk, nil
}

func (pkc *PublicKeysConfig) FindAndCacheEuropean(kid []byte) ([]interface{}, error) {
	return pkc.EuropeanPks.FindAndCacheEuropean(kid)
}
