package mobilecore

import (
	"encoding/base64"
	"github.com/go-errors/errors"
	"math"
	"strconv"
	"time"
)

func verifyDomestic(proof []byte, rules *domesticVerificationRules, now time.Time) (verificationDetails *VerificationDetails, err error) {
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

	// Build details
	verificationDetails = &VerificationDetails{
		CredentialVersion: strconv.Itoa(verifiedCred.CredentialVersion),
		IsSpecimen:        attributes["isSpecimen"],
		FirstNameInitial:  attributes["firstNameInitial"],
		LastNameInitial:   attributes["lastNameInitial"],
		BirthDay:          attributes["birthDay"],
		BirthMonth:        attributes["birthMonth"],
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

func checkDenylist(proofIdentifier []byte, denyList map[string]bool) error {
	proofIdentifierBase64 := base64.StdEncoding.EncodeToString(proofIdentifier)

	denied, ok := denyList[proofIdentifierBase64]
	if ok && denied {
		return errors.Errorf("The credential identifier was present in the proof identifier denylist")
	}

	return nil
}
