package mobilecore

import (
	"github.com/go-errors/errors"
	"math"
	"strconv"
	"time"
)

const (
	QR_VALID_FOR_SECONDS  = 180.0
	V1_VALIDITY_HOURS_STR = "40"
)

func verifyDomestic(proofBase45 []byte, now time.Time) (verificationResult *VerificationResult, err error) {
	verifiedCred, err := domesticVerifier.VerifyQREncoded(proofBase45)
	if err != nil {
		return nil, err
	}

	attributes := verifiedCred.Attributes
	var validFrom, validForHours, stripType string

	if verifiedCred.CredentialVersion == 1 {
		validFrom = attributes["sampleTime"]
		validForHours = V1_VALIDITY_HOURS_STR
		stripType = attributes["isPaperProof"]
	} else {
		validFrom = attributes["validFrom"]
		validForHours = attributes["validForHours"]
		stripType = attributes["stripType"]
	}

	err = checkValidity(validFrom, validForHours, now)
	if err != nil {
		return nil, err
	}

	err = checkFreshness(verifiedCred.UnixTimeSeconds, stripType, now)
	if err != nil {
		return nil, err
	}

	// Build result
	verificationResult = &VerificationResult{
		CredentialVersion: strconv.Itoa(verifiedCred.CredentialVersion),
		IsSpecimen:        attributes["isSpecimen"],
		FirstNameInitial:  attributes["firstNameInitial"],
		LastNameInitial:   attributes["lastNameInitial"],
		BirthDay:          attributes["birthDay"],
		BirthMonth:        attributes["birthMonth"],
	}

	return verificationResult, nil
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

func checkFreshness(generatedAtTimestamp int64, isPaperProofStr string, now time.Time) error {
	// Paper proof are exempt from this check
	if isPaperProofStr == "1" {
		return nil
	}

	// Check if the time between now and
	unixTimeNow := now.UTC().Unix()
	if math.Abs(float64(unixTimeNow)-float64(generatedAtTimestamp)) > QR_VALID_FOR_SECONDS {
		return errors.Errorf("The credential has been generated too long ago, or clock skew is too large")
	}

	return nil
}
