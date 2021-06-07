package mobilecore

import "encoding/json"

func ReadEuropeanCredential(proofPrefixed []byte) *Result {
	hcert, err := europeanHolder.ReadQREncoded(proofPrefixed)
	if err != nil {
		return WrappedErrorResult(err, "Could not read European credential")
	}

	hcertJson, err := json.Marshal(hcert)
	if err != nil {
		return WrappedErrorResult(err, "Could not JSON marshal hcert")
	}

	return &Result{hcertJson, ""}
}
