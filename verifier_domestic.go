package mobilecore

import (
	"github.com/go-errors/errors"
	"math"
	"strconv"
	"time"
)

func verifyDomestic(proof []byte, policy string, rules *domesticVerificationRules, now time.Time) (verificationDetails *VerificationDetails, err error) {
	verifiedCred, err := domesticVerifier.VerifyQREncoded(proof)
	if err != nil {
		return nil, err
	}

	err = checkDenylist(verifiedCred.ProofIdentifier, rules.ProofIdentifierDenylist)
	if err != nil {
		return nil, err
	}

	attributes := verifiedCred.Attributes
	err = checkValidity(attributes["validFrom"], attributes["validForHours"], now)
	if err != nil {
		return nil, err
	}

	isPaperProof := attributes["isPaperProof"]
	err = checkFreshness(verifiedCred.DisclosureTimeSeconds, isPaperProof, rules, now)
	if err != nil {
		return nil, err
	}

	err = checkPolicy(policy, verifiedCred.CredentialVersion, verifiedCred.Attributes)
	if err != nil {
		return nil, err
	}

	// Build details
	verificationDetails = &VerificationDetails{
		CredentialVersion: strconv.Itoa(verifiedCred.CredentialVersion),
		IsSpecimen:        attributes["isSpecimen"],
		IssuerCountryCode: "NL",

		FirstNameInitial: attributes["firstNameInitial"],
		LastNameInitial:  attributes["lastNameInitial"],
		BirthDay:         attributes["birthDay"],
		BirthMonth:       attributes["birthMonth"],
	}

	return verificationDetails, nil
}

func checkValidity(validFromStr string, validForHoursStr string, now time.Time) error {
	validFrom, err := strconv.ParseInt(validFromStr, 10, 64)
	if err != nil {
		return errors.WrapPrefix(err, "Could not parse validFrom as int", 0)
	}

	validForHours, err := strconv.ParseInt(validForHoursStr, 10, 0)
	if err != nil {
		return errors.WrapPrefix(err, "Could not parse validForHours as int", 0)
	}

	unixTimeNow := now.UTC().Unix()
	if unixTimeNow < validFrom {
		return errors.Errorf("The credential is not yet valid")
	}

	validUntil := validFrom + validForHours*60*60
	if unixTimeNow >= validUntil {
		return errors.Errorf("The credential is not valid anymore")
	}

	return nil
}

func checkFreshness(generatedAtTimestamp int64, isPaperProofStr string, rules *domesticVerificationRules, now time.Time) error {
	// Paper proof are exempt from this check
	if isPaperProofStr == "1" {
		return nil
	}

	// Check if the time between now and
	unixTimeNow := now.UTC().Unix()
	qrValidForSeconds := float64(rules.QRValidForSeconds)
	if math.Abs(float64(unixTimeNow)-float64(generatedAtTimestamp)) > qrValidForSeconds {
		return errors.Errorf("The credential has been generated too long ago, or clock skew is too large")
	}

	return nil
}

func checkPolicy(policy string, credentialVersion int, attributes map[string]string) error {
	// Credential version 2 doesn't contain any category, and is assumed to be valid for 2G
	if credentialVersion == 2 {
		return nil
	}

	// Any other credential version contains a category attribute with a category
	// The 3G policy allows any category
	if policy == VERIFICATION_POLICY_3G {
		return nil
	}

	// Otherwise, the credential must contain the 2G category attribute
	// TODO: During the migration period of 28 days after forced update, an empty category attribute
	//   is also allowed. This should be removed after the migration is complete
	if attributes["category"] == VERIFICATION_POLICY_2G || attributes["category"] == "" {
		return nil
	}

	return errors.Errorf("The credential did not contain the required 2G category")
}
