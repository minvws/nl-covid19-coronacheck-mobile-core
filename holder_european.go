package mobilecore

import (
	"encoding/json"
	"time"
)

func ReadEuropeanCredential(proofQREncoded []byte) *Result {
	// Read the proof
	hcert, err := europeanHolder.ReadQREncoded(proofQREncoded)
	if err != nil {
		return WrappedErrorResult(err, "Could not read European credential")
	}

	// If the credential is a specimen, set the expirationTime to a year in the future
	if hcert.ExpirationTime == HCERT_SPECIMEN_EXPIRATION_TIME {
		hcert.ExpirationTime = time.Now().Add(28 * 24 * time.Hour).Unix()
	}

	// Marshal to JSON
	hcertJson, err := json.Marshal(hcert)
	if err != nil {
		return WrappedErrorResult(err, "Could not JSON marshal hcert")
	}

	return &Result{hcertJson, ""}
}

func IsDCC(proofQREncoded []byte) bool {
	_, err := europeanHolder.ReadQREncoded(proofQREncoded)
	return err == nil
}

func IsForeignDCC(proofQREncoded []byte) bool {
	hcert, err := europeanHolder.ReadQREncoded(proofQREncoded)
	if err != nil {
		return false
	}

	// If the CWT issuer field specifies a foreign country code, it's a foreign DCC
	if hcert.Issuer != DCC_DOMESTIC_ISSUER_COUNTRY_CODE {
		return true
	}

	// A domestic CWT issuer field can still represent a CAS-island DCC,
	//  when it has a configured key with a present SAN which is not the domestic country code SAN
	pks, ok := europeanPksLookup[hcert.KIDB64]
	if !ok {
		return false
	}

	for _, pk := range pks {
		if len(pk.SubjectAltName) == 3 && pk.SubjectAltName != DCC_DOMESTIC_ISSUER_KEY_SAN {
			return true
		}
	}

	return false
}
