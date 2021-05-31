package mobilecore

import (
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/holder"
	"strings"
)

func ReadEuropeanCredential(proofPrefixed []byte) *Result {
	hcertJson, err := holder.ReadQREncoded(proofPrefixed)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not read European credential", 0))
	}

	return &Result{hcertJson, ""}
}

// Verification
// FIXME: Mock implementation for now
type VerificationResult struct {
	FirstNameInitial string `json:"firstNameInitial"`
	LastNameInitial  string `json:"lastNameInitial"`
	BirthDay         string `json:"birthDay"`
	BirthMonth       string `json:"birthMonth"`
}

type HCert struct {
	CredentialVersion int  `json:"credentialVersion"`
	ExpirationTime    int  `json:"expirationTime"`
	IssuedAt          int  `json:"issuedAt"`
	DCC               *DCC `json:"dcc"`
}

type DCC struct {
	DateOfBirth string   `json:"dob"`
	Name        *DCCName `json:"nam"`
}

type DCCName struct {
	GivenName  string `json:"gn"`
	FamilyName string `json:"fn"`
}

func verifyEuropean(proofQREncoded []byte) (attributes map[string]string, err error) {
	dgcJson, err := holder.ReadQREncoded(proofQREncoded)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not read credential", 0)
	}

	var hcert *HCert
	err = json.Unmarshal(dgcJson, &hcert)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not JSON unmarshal hcert", 0)
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

	// Turn into attributes
	return map[string]string{
		"credentialVersion": "1",
		"isSpecimen":        "0",
		"birthMonth":        dobParts[1],
		"birthDay":          dobParts[2],
		"firstNameInitial":  normalizedGivenName[0:1],
		"lastNameInitial":   normalizedFamilyName[0:1],
	}, nil
}
