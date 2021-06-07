package mobilecore

import (
	"github.com/go-errors/errors"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
	"strings"
	"unicode"
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

func verifyEuropean(proofQREncoded []byte) (*VerificationResult, error) {
	hcert, err := europeanVerifier.VerifyQREncoded(proofQREncoded)
	if err != nil {
		return nil, err
	}

	result, err := buildVerificationResult(hcert)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func buildVerificationResult(hcert *hcertcommon.HealthCertificate) (*VerificationResult, error) {
	// Determine issuer
	isNLDCC := "0"
	if hcert.Issuer == "NL" {
		isNLDCC = "1"
	}

	// Normalize date of birth
	dobParts := strings.Split(hcert.DCC.DateOfBirth, "-")
	for i := len(dobParts); i < 3; i++ {
		dobParts = append(dobParts, "XX")
	}

	// Normalize name
	normalizedGivenName, err := normalizeName(hcert.DCC.Name.GivenName)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not normalize given name", 0)
	}

	normalizedFamilyName, err := normalizeName(hcert.DCC.Name.FamilyName)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not normalize family name", 0)
	}

	return &VerificationResult{
		CredentialVersion: "1",
		IsSpecimen:        "0",
		BirthMonth:        dobParts[1],
		BirthDay:          dobParts[2],
		FirstNameInitial:  normalizedGivenName[0:1],
		LastNameInitial:   normalizedFamilyName[0:1],

		IsNLDCC: isNLDCC,
	}, nil
}

// Doesn't do prefixes like 't, and 's- yet
func normalizeName(input string) (string, error) {
	rf := transform.RemoveFunc(func(r rune) bool { //nolint
		return unicode.Is(unicode.Mn, r) && !unicode.Is(unicode.Punct, r)
	})

	t := transform.Chain(norm.NFD, rf, norm.NFC)
	normalized, _, err := transform.String(t, input)
	if err != nil {
		return "", errors.WrapPrefix(err, "Could not normalize name", 0)
	}

	if len(normalized) == 0 {
		return "", errors.Errorf("Normalization result is empty")
	}

	return normalized, err
}
