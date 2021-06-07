package mobilecore

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"os"
)

type PublicKeysConfig struct {
	DomesticPks DomesticPksLookup `json:"nl_keys"`
	EuropeanPks EuropeanPksLookup `json:"eu_keys"`

	// DEPRECATED: Remove this struct when the transition to nl_keys is complete
	LegacyDomesticPks []*AnnotatedDomesticPk `json:"cl_keys"`
}

type DomesticPksLookup map[string]*AnnotatedDomesticPk
type EuropeanPksLookup map[string][]*AnnotatedEuropeanPk

type AnnotatedDomesticPk struct {
	PkXml    []byte          `json:"public_key"`
	LoadedPk *gabi.PublicKey `json:"-"`

	// DEPRECATED: Remove this field together with LegacyDomesticPks
	KID string `json:"id"`
}

type AnnotatedEuropeanPk struct {
	SubjectPk []byte   `json:"subjectPk"`
	KeyUsage  []string `json:"keyUsage"`

	// LoadedPK is either of type *ecdsa.PublicKey or *rsa.PublicKey
	LoadedPk interface{} `json:"-"`
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
	// Check if key id is present
	kidB64 := base64.StdEncoding.EncodeToString(kid)
	annotatedPks, ok := pkc.EuropeanPks[kidB64]
	if !ok {
		return nil, errors.Errorf("Could not find European public key for this key id")
	}

	// Collect all (cached) public keys
	pks := make([]interface{}, 0, len(annotatedPks))
	for _, annotatedPk := range annotatedPks {
		if annotatedPk.LoadedPk == nil {
			// Allow parsing errors at this stage, so that kid collisions
			//  cannot prevent another key from verifying
			annotatedPk.LoadedPk, _ = x509.ParsePKIXPublicKey(annotatedPk.SubjectPk)
		}

		pks = append(pks, annotatedPk.LoadedPk)
	}

	if len(pks) == 0 {
		return nil, errors.Errorf("Could not find any valid European public keys for this key id")
	}

	return pks, nil
}
