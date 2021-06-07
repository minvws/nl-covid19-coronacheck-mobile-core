package mobilecore

import (
	"github.com/go-errors/errors"
	"math"
	"strconv"
	"time"
)

const (
	QR_VALID_FOR_SECONDS = 180.0
)

func verifyDomestic(proofBase45 []byte) (attributes map[string]string, err error) {
	verifiedCred, err := domesticVerifier.VerifyQREncoded(proofBase45)
	if err != nil {
		return nil, err
	}

	attributes = verifiedCred.Attributes
	err = checkValidity(attributes["validFrom"], attributes["validForHours"])
	if err != nil {
		return nil, err
	}

	err = checkFreshness(verifiedCred.UnixTimeSeconds, attributes["isPaperProof"])
	if err != nil {
		return nil, err
	}

	// Add the credential version
	attributes = verifiedCred.Attributes
	attributes["credentialVersion"] = strconv.Itoa(verifiedCred.CredentialVersion)

	return attributes, nil
}

func checkValidity(validFromStr string, validForHoursStr string) error {
	validFrom, err := strconv.ParseInt(validFromStr, 10, 64)
	if err != nil {
		return errors.WrapPrefix(err, "Could not parse validFrom as int", 0)
	}

	validForHours, err := strconv.ParseInt(validForHoursStr, 10, 0)
	if err != nil {
		return errors.WrapPrefix(err, "Could not parse validForHours as int", 0)
	}

	unixTimeNow := time.Now().UTC().Unix()
	if unixTimeNow < validFrom {
		return errors.Errorf("The credential is not yet valid")
	}

	validUntil := validFrom + validForHours*60*60
	if unixTimeNow >= validUntil {
		return errors.Errorf("The credential is not valid anymore")
	}

	return nil
}

func checkFreshness(generatedAtTimestamp int64, isPaperProofStr string) error {
	// Paper proof are exempt from this check
	if isPaperProofStr == "1" {
		return nil
	}

	// Check if the time between now and
	unixTimeNow := time.Now().UTC().Unix()
	if math.Abs(float64(unixTimeNow)-float64(generatedAtTimestamp)) > QR_VALID_FOR_SECONDS {
		return errors.Errorf("The credential has been generated too long ago, or clock skew is too large")
	}

	return nil
}
