package mobilecore

import (
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/holder"
)

func ReadEuropeanCredential(proofPrefixed []byte) *Result {
	hcertJson, err := holder.ReadQREncoded(proofPrefixed)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not read European credential", 0))
	}

	return &Result{hcertJson, ""}
}
